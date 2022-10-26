import argparse
import ast
import json
import os

from saitest_report_base import *


def get_parser(description=None):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--path", "-p", type=str, default="files/sai_test", help="file/directory to scan.")
    parser.add_argument("--save_path", "-sp", type=str, default="result", help="file/directory to save compressed results.")
    args = parser.parse_args()
    return args


def seach_defalt_parms(method_name, idx):
    with open(SAI_ADAPTER_DIRPATH, 'r') as rf:
        dic = json.load(rf)
        if method_name in dic:
            return dic[method_name][idx - 1]
    return "unknown"


class SAICoverageScanner(object):

    def __init__(self, parser):
        self.case_path = parser.path
        self.save_path = parser.save_path
        self.header_path = SAI_HEADER_FILE
        self.final_coverage = list()

    def parse(self):
        '''
        structure:
        {file name : class_case_dict}
        '''
        for (root, _, filenames) in os.walk(self.case_path):
            for filename in filenames:
                if filename.endswith(".py") and filename not in IGNORE_FILE_LIST and "helper" not in filename.lower():
                    with open(root + "/" + filename, "r") as f:
                        code = f.read()
                        f_ast = ast.parse(code)
                        self.visit_AST(f_ast, filename)
                        self.final_coverage = []


    def visit_AST(self, raw_ast, filename):
        '''
        structure:
        {class name : {method name : [SAI apis]}}
        '''
        for node in raw_ast.body:
            if isinstance(node, ast.ClassDef):
                self.visit_ClassDef(node, filename)


    def visit_ClassDef(self, node, filename):
        '''
        structure:
        {method name : [SAI apis]}
        '''
        method_intf_dict = dict()
        for n in node.body:
            if self.is_skipped(n):
                return 
            if isinstance(n, ast.FunctionDef):
                if n.name not in method_intf_dict:  # Setup, TearDown, etc
                    method_intf_dict[n.name] = dict()
                self.visit_FunctionDef(n, method_intf_dict, filename, node.name)


    def visit_FunctionDef(self, node, method_intf_dict, filename, node_name):
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                if "test" in child.func.id.lower() or SAI_API_PREFIX in child.func.id and "t" not in child.func.id.split("_"):
                    if child.func.id not in method_intf_dict[node.name]:
                        method_intf_dict[node.name][child.func.id] = list()
                    print('Scanning', node.name, child.func.id, '...')

                    if len(child.args) > 1:
                        for idx, arg in enumerate(child.args):
                            if idx == 0: continue
                            v = self.get_attr_and_values_arg(arg)
                            if v is None: continue
                            attr_name = seach_defalt_parms(child.func.id, idx)
                            method_intf_dict[node.name][child.func.id].append({attr_name: v})

                    for keyword in child.keywords:
                        v = self.get_attr_and_values_keywordval(keyword.value)
                        if v is None: continue
                        method_intf_dict[node.name][child.func.id].append({keyword.arg: v})

            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if "test" in child.func.attr.lower() or SAI_API_PREFIX in child.func.attr and "t" not in child.func.attr.split("_"):
                    if child.func.attr not in method_intf_dict[node.name]:
                        method_intf_dict[node.name][child.func.attr] = list()
                    print('Scanning', node.name, child.func.attr, '...')

                    if len(child.args) > 1:
                        for idx, arg in enumerate(child.args):
                            if idx == 0: continue
                            v = self.get_attr_and_values_arg(arg)
                            if v is None: continue
                            attr_name = seach_defalt_parms(child.func.attr, idx)
                            method_intf_dict[node.name][child.func.attr].append({attr_name: v})

                    for keyword in child.keywords:
                        v = self.get_attr_and_values_keywordval(keyword.value)
                        if v is None: continue
                        method_intf_dict[node.name][child.func.attr].append({keyword.arg: v})

        self.generate_flatten_report(method_intf_dict, filename, node_name)


    def is_skipped(self, node):
        if isinstance(node, ast.FunctionDef) and node.name == "setUp":
            for cell in ast.walk(node):
                if isinstance(cell, ast.FunctionDef) and len(cell.body):
                    for body in cell.body:
                        if isinstance(body, ast.Expr) and isinstance(body.value, ast.Call):
                            for keyword in body.value.keywords:
                                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str) and "SKIP" in keyword.value.value:
                                    print(keyword.value.value)
                                    return True
        return False


    def get_attr_and_values_arg(self, arg):
        if isinstance(arg, ast.Name):
            v = arg.id
        elif isinstance(arg, ast.Constant):
            v = str(arg.value).lower()
        elif isinstance(arg, ast.Attribute):
            if isinstance(arg.value, ast.Attribute) or isinstance(arg.value, ast.Subscript):
                v = "values"
            else:
                v = arg.value.id + '.' + arg.attr
        elif isinstance(arg, ast.Subscript):
            if isinstance(arg.slice, ast.Constant):
                subscrpt = str(arg.slice.value)
                v = arg.value.value.id + '.' + arg.value.attr + '[' + subscrpt + ']'
            elif isinstance(arg.slice, ast.Name):
                subscrpt = arg.slice.id
                v = arg.value.value.id + '.' + arg.value.attr + '[' + subscrpt + ']'
            elif isinstance(arg.value, ast.Attribute) or isinstance(arg.value, ast.Subscript) or isinstance(arg.value, ast.Name):
                v = "values"
        elif isinstance(arg, ast.List):
            for elt in arg.elts:
                if isinstance(elt, ast.Name):
                    v =  '[' + elt.id + ']'
                elif isinstance(elt, ast.Attribute):
                    v = "values"
                elif isinstance(elt, ast.List):
                    for e in elt.elts:
                        if isinstance(e, ast.Name):
                            v =  '[' + e.id + ']'
                        elif isinstance(e, ast.Attribute):
                            v = "values"
        elif isinstance(arg, ast.Dict):
            v = "dict type with { : }"
        elif isinstance(arg, ast.Call):  # embedded method invocation
            return None
        else:
            print()
        return v

    def get_attr_and_values_keywordval(self, keyword_value):
        if isinstance(keyword_value, ast.Name):
            v = keyword_value.id
        elif isinstance(keyword_value, ast.Constant):
            v = str(keyword_value.value).lower()
        elif isinstance(keyword_value, ast.Attribute):
            if isinstance(keyword_value.value, ast.Attribute) or isinstance(keyword_value.value, ast.Subscript):
                v = "values"
            else:
                v = keyword_value.value.id + '.' + keyword_value.attr
        elif isinstance(keyword_value, ast.Subscript):
            if isinstance(keyword_value.slice, ast.Constant):
                subscrpt = str(keyword_value.slice.value)
                v = keyword_value.value.value.id + '.' + keyword_value.value.attr + '[' + subscrpt + ']'
            elif isinstance(keyword_value.slice, ast.Name):
                subscrpt = keyword_value.slice.id
                v = keyword_value.value.value.id + '.' + keyword_value.value.attr + '[' + subscrpt + ']'
            elif isinstance(keyword_value.value, ast.Attribute) or isinstance(keyword_value.value, ast.Subscript) or isinstance(keyword_value.value, ast.Name):
                v = "values"
        elif isinstance(keyword_value, ast.List):
            if isinstance(keyword_value.elts[0], ast.Name):
                v =  '[' + keyword_value.elts[0].id + ']'
            elif isinstance(keyword_value.elts[0], ast.Attribute):
                v = "values"
        elif isinstance(keyword_value, ast.BinOp) or isinstance(keyword_value, ast.UnaryOp):
            v = "values"
        elif isinstance(keyword_value, ast.Call) or isinstance(keyword_value, ast.IfExp):  # embedded method invocation or if expression
            return None
        else:
            print()
        return v


    def parse_header(self, header_path):
        data = dict()
        with open(header_path, 'r') as f:
            data = json.load(f)
        return data


    def generate_flatten_report(self, method_case_dict, file_name, class_name):
        covered_methods = set()
        header_data = self.parse_header(self.header_path)

        for (method_name, sai_apis) in method_case_dict.items():
            for (attr_name, attr_values) in sai_apis.items():
                for sai_intf in attr_values:
                    if "sai_thrift_" not in attr_name:
                        continue
                    # remove sai_thrift_xxxxx and change to sai_xxxxx_fn for header key
                    header_key = "sai_" + attr_name.split("sai_thrift_")[1] + "_fn"
                    covered_methods.add(header_key)
                    # need saiintf_target file to have sai header info
                    if header_key in header_data:
                        test_set = "t0" if 'sai_test' in self.case_path else "ptf"
                        test_invocation = TestInvocation(
                            file_name=file_name,
                            class_name=class_name,
                            case_name=method_name,
                            case_invoc=attr_name,
                            sai_header=file_name,
                            saiintf_id=header_data[header_key]["intf_groupname"],
                            saiintf_method_table=header_data[header_key]["intf_groupalias"],
                            saiintf_name=header_data[header_key]["intf_name"],
                            saiintf_alias=header_data[header_key]["intf_alias"],
                            test_set=test_set,
                            test_platform="vms3-t1-dx010-1",
                            platform_purpose_attr="",
                            attr_name=next(iter(sai_intf)),
                            attr_value=sai_intf[next(iter(sai_intf))]
                        )

                        self.final_coverage.append(test_invocation.__dict__)

        # self.fill_uncovered_api(covered_methods, header_data)
        if len(self.final_coverage) == 0:
            return
        os.makedirs(self.save_path, exist_ok=True)
        with open(os.path.join(self.save_path, file_name[:-2]+'json'), 'w+') as f:
            json.dump(self.final_coverage, f, indent=4)


    def fill_uncovered_api(self, covered_methods, header_data):
        uncovered_methods = set(header_data.keys()) - covered_methods

        for uncovered_key in uncovered_methods:
            test_set = "t0" if 'sai_test' in self.case_path else "ptf"
            test_invocation = TestInvocation(
                file_name="uncovered",
                case_name="uncovered",
                class_name="uncovered",
                case_invoc="uncovered",
                sai_header="uncovered",
                saiintf_id=header_data[uncovered_key]["intf_groupname"],
                saiintf_method_table=header_data[uncovered_key]["intf_groupalias"],
                saiintf_name=header_data[uncovered_key]["intf_name"],
                saiintf_alias=header_data[uncovered_key]["intf_alias"],
                test_set=test_set,
                test_platform="vms3-t1-dx010-1",
                platform_purpose_attr="",
                attr_name="",
                attr_value=""
            )

            self.final_coverage.append(test_invocation.__dict__)


if __name__ == '__main__':
    parser = get_parser()
    scanner = SAICoverageScanner(parser)
    scanner.parse()
