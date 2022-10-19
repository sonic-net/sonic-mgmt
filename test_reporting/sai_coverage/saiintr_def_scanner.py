import ast
import json
import os


def seach_defalt_parms(root_path, save_path):
    good_file = (file for file in os.listdir(root_path) if file[-3:] == '.py' and file != '__init__.py')
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
    root_path = "Path/to/Your/SAI_API/Definition"
    save_path = "sai_adaptor.json"
    seach_defalt_parms(root_path, save_path)  # Static Scanning
