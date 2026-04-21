#!/usr/bin/env python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import ast
from pathlib import PosixPath
import yaml
import argparse
import os


def read_docstring(filename):

    """
    Search for assignment of the DOCUMENTATION and EXAMPLES variables in the given file.
    Parse DOCUMENTATION from YAML and return the YAML doc or None together with EXAMPLES, as plain text.
    """

    data = {
        'doc': None,
        'plainexamples': None,
        'returndocs': None,
        'metadata': None,  # NOTE: not used anymore, kept for compat
        'seealso': None,
    }

    string_to_vars = {
        'DOCUMENTATION': 'doc',
        'EXAMPLES': 'plainexamples',
        'RETURN': 'returndocs',
        'ANSIBLE_METADATA': 'metadata',  # NOTE: now unused, but kept for backwards compat
    }

    try:
        with open(filename, 'rb') as b_module_data:
            M = ast.parse(b_module_data.read())

        for child in M.body:
            if isinstance(child, ast.Assign):
                for t in child.targets:
                    try:
                        theid = t.id
                    except AttributeError:
                        # skip errors can happen when trying to use the normal code
                        # sys.stderr.write("Failed to assign id for %s on %s, skipping\n" % (t, filename))
                        continue

                    if theid in string_to_vars:
                        varkey = string_to_vars[theid]
                        if isinstance(child.value, ast.Dict):
                            data[varkey] = ast.literal_eval(child.value)
                        else:
                            if theid != 'EXAMPLES':
                                # string should be yaml if already not a dict
                                data[varkey] = child.value.s

                        # sys.stderr.write('assigned: %s\n' % varkey)

    except Exception:
        # sys.stderr.write("unable to parse %s" % filename)
        return

    return yaml.safe_load(data["doc"]) if data["doc"] is not None else None


def is_extending_collection(result, col_fqcn):
    if result:
        for x in result.get("extends_documentation_fragment", []):
            if x.startswith(col_fqcn):
                return True
    return False


def main():

    parser = argparse.ArgumentParser(
        description="list modules with inherited doc fragments from kubernetes.core that need rendering to deal with Galaxy/AH lack of functionality."
    )
    parser.add_argument(
        "-c", "--collection-path", type=str, default=os.getcwd(), help="path to the collection"
    )

    args = parser.parse_args()

    path = PosixPath(args.collection_path) / PosixPath("plugins/modules")
    output = []
    for d in path.iterdir():
        if d.is_file():
            result = read_docstring(str(d))
            if is_extending_collection(result, "kubernetes.core."):
                output.append(d.stem.replace(".py", ""))
    print("\n".join(output))


if __name__ == '__main__':
    main()
