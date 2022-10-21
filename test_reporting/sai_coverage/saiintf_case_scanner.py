import argparse
import ast
import json
import os

from saitest_report_base import *


def get_parser(description=None):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--path", "-p", type=str, help="file/directory to scan.")
    parser.add_argument("--save_compress_path", "-cp", type=str, help="file/directory to save compressed results.")
    parser.add_argument("--save_flatten_path", "-fp", type=str, help="file/directory to save flatten results.")
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
        self.save_compress_path = parser.save_compress_path
        self.save_flatten_path = parser.save_flatten_path
        self.header_path = SAI_HEADER_FILE

    def parse(self):
        # {file name : class_case_dict}
        file_class_dict = dict()

        for (root, _, filenames) in os.walk(self.case_path):
            for filename in filenames:
                if filename.endswith(".py") and filename not in IGNORE_FILE_LIST and "helper" not in filename.lower():
                    with open(root + "/" + filename, "r") as f:
                        code = f.read()
                        f_ast = ast.parse(code)
                        file_class_dict[filename] = self.visit_AST(f_ast)

        with open(self.save_compress_path, 'w+') as f:
            json.dump(file_class_dict, f, indent=4, cls=SAIJsonEncoder)

        self.compose_coverage_report(file_class_dict)

    def visit_AST(self, raw_ast):
        # {class name : {method name : [SAI apis]}}
        class_case_dict = dict()

        for node in raw_ast.body:
            if isinstance(node, ast.ClassDef):
                class_case_dict[node.name] = self.visit_ClassDef(node)

        return class_case_dict

    def visit_ClassDef(self, node):
        # {method name : [SAI apis]}
        method_intf_dict = dict()

        for n in node.body:
            if self.is_skipped(n):
                return method_intf_dict
            if isinstance(n, ast.FunctionDef):
                if n.name not in method_intf_dict:  # Setup, TearDown, etc
                    method_intf_dict[n.name] = dict()
                self.visit_FunctionDef(n, method_intf_dict)

        return method_intf_dict

    def visit_FunctionDef(self, node, method_intf_dict):

        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                if "test" in child.func.id.lower() or SAI_API_PREFIX in child.func.id and "t" not in child.func.id.split("_"):

                    if child.func.id not in method_intf_dict[node.name]:
                        method_intf_dict[node.name][child.func.id] = list()
                    print(node.name, child.func.id)

                    if len(child.args) > 1:
                        for idx, arg in enumerate(child.args):
                            if idx == 0: continue

                            v = self.get_attr_and_values_arg(arg)
                            if v is None:continue

                            attr_name = seach_defalt_parms(child.func.id, idx)
                            print('name =', attr_name, ', value =', v)
                            method_intf_dict[node.name][child.func.id].append({attr_name: v})

                    for keyword in child.keywords:
                        v = self.get_attr_and_values_keywordval(keyword.value)
                        if v is None: continue

                        print('name =', keyword.arg, ', value =', v)
                        method_intf_dict[node.name][child.func.id].append({keyword.arg: v})

                    print()

            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if "test" in child.func.attr.lower() or SAI_API_PREFIX in child.func.attr and "t" not in child.func.attr.split("_"):
                    if child.func.attr not in method_intf_dict[node.name]:
                        method_intf_dict[node.name][child.func.attr] = list()
                    print(node.name, child.func.attr)

                    if len(child.args) > 1:
                        for idx, arg in enumerate(child.args):
                            if idx == 0: continue

                            v = self.get_attr_and_values_arg(arg)
                            if v is None:continue

                            attr_name = seach_defalt_parms(child.func.attr, idx)
                            print('name =', attr_name, ', value =', v)
                            method_intf_dict[node.name][child.func.attr].append({attr_name: v})

                    for keyword in child.keywords:
                        v = self.get_attr_and_values_keywordval(keyword.value)
                        if v is None: continue

                        print('name =', keyword.arg, ', value =', v)
                        method_intf_dict[node.name][child.func.attr].append({keyword.arg: v})

                    print()

    def is_skipped(self, node):
        if isinstance(node, ast.FunctionDef) and node.name == "setUp":
            for cell in ast.walk(node):
                if (isinstance(cell, ast.FunctionDef) and
                    len(cell.body) > 0 and
                    isinstance(cell.body[-1], ast.Expr) and 
                    isinstance(cell.body[-1].value, ast.Call) and 
                    len(cell.body[-1].value.keywords) > 0 and
                    isinstance(cell.body[-1].value.keywords[0].value, ast.Constant) and 
                    isinstance(cell.body[-1].value.keywords[0].value.value, str) and 
                    "SKIP" in cell.body[-1].value.keywords[0].value.value):
                    print(cell.body[-1].value.keywords[0].value.value)
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

    def compose_coverage_report(self, file_class_dict):
        header_data = self.parse_header(self.header_path)
        final_coverage = list()

        covered_methods = set()

        for (file_name, class_case_dict) in file_class_dict.items():
            for (class_name, method_case_dict) in class_case_dict.items():
                for (method_name, sai_apis) in method_case_dict.items():
                    for (attr_name, attr_values) in sai_apis.items():
                        for i, sai_intf in enumerate(attr_values):
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
                                    case_name=method_name,
                                    class_name=class_name,
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

                                final_coverage.append(test_invocation.__dict__)

        final_coverage = self.fill_uncovered_api(covered_methods, header_data, final_coverage)
        with open(self.save_flatten_path, 'w+') as f:
            json.dump(final_coverage, f, indent=4)

    def fill_uncovered_api(self, covered_methods, header_data, final_coverage):
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

            final_coverage.append(test_invocation.__dict__)

        return final_coverage


if __name__ == '__main__':
    parser = get_parser()
    scanner = SAICoverageScanner(parser)
    scanner.parse()
