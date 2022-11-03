"""
This file scans all SAI interface in a given directory of files. Each file is corresponds to a json result.
The key points are AST (abstract syntax tree) and DFS(depth first search).
"""

import argparse
import ast
import json
import os

from multipledispatch import dispatch

from constant import (FINAL_RESULT_SAVE_DIR, IGNORE_FILE_LIST,
                      PRIORI_RESULT_SAVE_DIR, SAI_API_PREFIX,
                      SAI_HEADER_FILENAME, UNRUNNABLE_TAG_LIST)
from data_model.test_invocation import TestInvocation
from sai_report_utils import seach_defalt_parms


def get_parser(description="SAI Interface Scanner"):
    """
    Parse command line
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--path", "-p", type=str,
                        default="../CaseScanner/files/ptf", help="directory to scan.")
    parser.add_argument("--save_path", "-sp", type=str, default=FINAL_RESULT_SAVE_DIR,
                        help="directory to save the compressed results.")
    args = parser.parse_args()
    return args


class SAICoverageScanner(object):
    """
    Get and format all SAI interface information
    """

    def __init__(self, parser):
        self.case_path = parser.path
        self.save_path = parser.save_path
        self.header_path = os.path.join(
            PRIORI_RESULT_SAVE_DIR, SAI_HEADER_FILENAME)
        self.final_coverage = list()

    def parse(self):
        '''
        Parse file level
        '''
        for (root, _, filenames) in os.walk(self.case_path):
            for filename in filenames:
                if filename.endswith(".py") and \
                   filename not in IGNORE_FILE_LIST and \
                   "helper" not in filename.lower():
                    with open(root + "/" + filename, "r") as f:
                        test_set = "t0" if 'sai_test' in root else "ptf"
                        code = f.read()
                        f_ast = ast.parse(code)
                        self.parse_class(f_ast, filename, test_set, root)
                        self.final_coverage = []

    def parse_class(self, raw_ast, file_name, test_set, sai_folder):
        '''
        Parse class level

        Args:
            node: AST node
            file_name: file name
            test_set: distinguish test set ("t0" or "ptf")
            sai_folder: folder name of the scanning file
        '''
        for node in raw_ast.body:
            if isinstance(node, ast.ClassDef):
                runnable = True
                if len(node.decorator_list) > 0:
                    runnable = self.parse_decorator_list(node)
                self.parse_method(node, file_name, node.name,
                                  test_set, runnable, sai_folder)

    def parse_method(self, node: ast.ClassDef, file_name, class_name,
                     test_set, runnable, sai_folder):
        '''
        parse method level

        Args:
            node: AST node
            file_name: file name
            class_name: class name
            test_set: distinguish test set ("t0" or "ptf")
            runnable: distinguish whether case runnable
            sai_folder: folder name of the scanning file
        '''
        for n in node.body:
            if isinstance(n, ast.FunctionDef):
                self.parse_sai_interface(
                    n, file_name, class_name, n.name, test_set, runnable, sai_folder)

    def parse_sai_interface(self, node: ast.FunctionDef, file_name, class_name, method_name,
                            test_set, runnable, sai_folder):
        '''
        parse SAI interface level

        Args:
            node: AST node
            file_name: file name
            class_name: class name
            method_name: method name
            test_set: distinguish test set ("t0" or "ptf")
            runnable: distinguish whether case runnable
            sai_folder: folder name of the scanning file
        '''
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                sai_interface = child.func.id
                if SAI_API_PREFIX in sai_interface and "t" not in sai_interface.split("_"):
                    self.parse_ast_name(
                        child, file_name, class_name, method_name, sai_interface, test_set, runnable, sai_folder)

            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                sai_interface = child.func.attr
                if SAI_API_PREFIX in sai_interface and "t" not in sai_interface.split("_"):
                    self.parse_ast_attribute(
                        child, file_name, class_name, method_name,
                        sai_interface, test_set, runnable, sai_folder)

    def parse_ast_name(self, child: ast.Call, file_name, class_name, method_name, sai_interface,
                       test_set, runnable, sai_folder):
        '''
        parse Attribute level (child.func : ast.Name)

        Args:
            child: AST child node
            file_name: file name
            class_name: class name
            method_name: method name
            sai_interface: SAI interface name
            test_set: distinguish test set ("t0" or "ptf")
            runnable: distinguish whether case runnable
            sai_folder: folder name of the scanning file
        '''
        print('Scanning', method_name, sai_interface, '...')
        if len(child.args) > 1:
            for idx, arg in enumerate(child.args):
                if idx == 0:
                    continue

                v = self.get_attr_and_values_arg(arg)
                if v is None:
                    continue

                attr_key = seach_defalt_parms(sai_interface, idx)
                attr_val = v
                self.construct_invocation_data(file_name, class_name, method_name, sai_interface,
                                               attr_key, attr_val, test_set, runnable, sai_folder)

        for keyword in child.keywords:
            v = self.get_attr_and_values_arg(keyword.value)
            if v is None:
                continue

            attr_key = keyword.arg
            attr_val = v
            self.construct_invocation_data(
                file_name, class_name, method_name, sai_interface,
                attr_key, attr_val, test_set, runnable, sai_folder)

    def parse_ast_attribute(self, child: ast.Call, file_name, class_name, method_name, sai_interface,
                            test_set, runnable, sai_folder):
        '''
        parse Attribute level (child.func : ast.Attribute)

        Args:
            child: AST child node
            file_name: file name
            class_name: class name
            method_name: method name
            sai_interface: SAI interface name
            test_set: distinguish test set ("t0" or "ptf")
            runnable: distinguish whether case runnable
            sai_folder: folder name of the scanning file
        '''
        print('Scanning', method_name, sai_interface, '...')
        if len(child.args) > 1:
            for idx, arg in enumerate(child.args):
                if idx == 0:
                    continue

                v = self.get_attr_and_values_arg(arg)
                if v is None:
                    continue

                attr_key = seach_defalt_parms(sai_interface, idx)
                attr_val = v
                self.construct_invocation_data(
                    file_name, class_name, method_name, sai_interface, attr_key, attr_val,
                    test_set, runnable, sai_folder)

        for keyword in child.keywords:
            v = self.get_attr_and_values_arg(keyword.value)
            if v is None:
                continue

            attr_key = keyword.arg
            attr_val = v
            self.construct_invocation_data(
                file_name, class_name, method_name, sai_interface, attr_key, attr_val, test_set, runnable, sai_folder)

    def construct_invocation_data(self, file_name, class_name, method_name, sai_interface, attr_key, attr_val,
                                  test_set, runnable, sai_folder):
        '''
        Construct SAI interface invocation report

        Args:
            file_name: file name
            class_name: class name
            method_name: method name
            sai_interface: SAI interface name
            attr_key: Attribute name
            attr_val: Attribute value
            test_set: distinguish test set ("t0" or "ptf")
            runnable: distinguish whether case runnable
            sai_folder: folder name of the scanning file
        '''
        header_data = self.parse_header(self.header_path)
        header_key = "sai_" + sai_interface.split("sai_thrift_")[1] + "_fn"
        if header_key not in header_data:
            return
        test_invocation = TestInvocation(
            file_name=file_name,
            class_name=class_name,
            case_name=method_name,
            case_invoc=sai_interface,
            sai_header=file_name,
            saiintf_id=header_data[header_key]["intf_groupname"],
            saiintf_method_table=header_data[header_key]["intf_groupalias"],
            saiintf_name=header_data[header_key]["intf_name"],
            saiintf_alias=header_data[header_key]["intf_alias"],
            test_set=test_set,
            test_platform="vms3-t1-dx010-1" if runnable else "",
            platform_purpose_attr="",
            attr_name=attr_key,
            attr_value=attr_val,
            runnable=runnable,
            sai_folder=sai_folder,
        )
        self.final_coverage.append(test_invocation.__dict__)

        os.makedirs(self.save_path, exist_ok=True)
        with open(os.path.join(self.save_path, file_name[:-2]+'json'), 'w+') as f:
            json.dump(self.final_coverage, f, indent=4)

    @dispatch(ast.Name)
    def get_attr_and_values_arg(self, arg: ast.Name) -> str:  # noqa: F811
        return arg.id

    @dispatch(ast.Constant)
    def get_attr_and_values_arg(self, arg: ast.Constant) -> str:  # noqa: F811
        return str(arg.value).lower()

    @dispatch(ast.Attribute)
    def get_attr_and_values_arg(self, arg: ast.Attribute) -> str:  # noqa: F811
        if isinstance(arg.value, ast.Attribute) or isinstance(arg.value, ast.Subscript):
            return ("values")
        else:
            return (arg.value.id + '.' + arg.attr)

    @dispatch(ast.Subscript)
    def get_attr_and_values_arg(self, arg: ast.Subscript) -> str:  # noqa: F811
        if isinstance(arg.slice, ast.Constant):
            subscrpt = str(arg.slice.value)
            v = arg.value.value.id + '.' + \
                arg.value.attr + '[' + subscrpt + ']'
        elif isinstance(arg.slice, ast.Name):
            subscrpt = arg.slice.id
            v = arg.value.value.id + '.' + \
                arg.value.attr + '[' + subscrpt + ']'
        elif isinstance(arg.value, ast.Attribute) or \
                isinstance(arg.value, ast.Subscript) or \
                isinstance(arg.value, ast.Name):
            v = "values"
        return v

    @dispatch(ast.List)
    def get_attr_and_values_arg(self, arg: ast.List) -> str:  # noqa: F811
        for elt in arg.elts:
            if isinstance(elt, ast.Name):
                v = '[' + elt.id + ']'
            elif isinstance(elt, ast.Attribute):
                v = "values"
            elif isinstance(elt, ast.List):
                for e in elt.elts:
                    if isinstance(e, ast.Name):
                        v = '[' + e.id + ']'
                    elif isinstance(e, ast.Attribute):
                        v = "values"
        return v

    @dispatch(ast.Dict)
    def get_attr_and_values_arg(self, arg: ast.Dict) -> str:  # noqa: F811
        return "dict type with { : }"

    @dispatch(ast.BinOp)
    def get_attr_and_values_arg(self, arg: ast.BinOp) -> str:  # noqa: F811
        return "dict type with { : }"

    @dispatch(ast.UnaryOp)
    def get_attr_and_values_arg(self, arg: ast.UnaryOp) -> str:  # noqa: F811
        return "dict type with { : }"

    @dispatch(ast.Call)
    def get_attr_and_values_arg(self, arg: ast.Call) -> None:  # noqa: F811
        return None

    @dispatch(ast.IfExp)
    def get_attr_and_values_arg(self, arg: ast.IfExp) -> None:  # noqa: F811
        return None

    def parse_header(self, header_path):
        '''
        Parse SAI header file

        Args:
            header_path: sai_header file path

        Return:
            data: loaded sai_header file
        '''
        data = dict()
        with open(header_path, 'r') as f:
            data = json.load(f)
        return data

    def parse_decorator_list(self, node: ast.ClassDef) -> bool:
        '''
        Parse decorator list, to distinguish whether the scanned case is runnable

        Args:
            node: AST node

        Return:
            boolean: runnable or not
        '''
        for decorator_val in node.decorator_list:
            if isinstance(decorator_val, ast.Call):
                for arg in decorator_val.args:
                    if isinstance(arg, ast.Constant) and arg.value in UNRUNNABLE_TAG_LIST:
                        return False
        return True


if __name__ == '__main__':
    parser = get_parser()
    scanner = SAICoverageScanner(parser)
    scanner.parse()
