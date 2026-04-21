from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
import json
import os

try:
    from shlex import quote
except ImportError:
    from pipes import quote


def escape_param(param):
    '''
    Escapes the given parameter
    @param - The parameter to escape
    '''
    return quote(param)


def add_arg_to_cmd(cmd_list, param_name, param_value, is_bool=False, omit=None):
    """
    @cmd_list - List of cmd args.
    @param_name - Param name / flag.
    @param_value - Value of the parameter.
    @is_bool - Flag is a boolean and has no value.
    @omit - List of parameter to omit from the command line.
    """
    if param_name.replace('-', '') not in omit:
        if is_bool is False and param_value is not None:
            cmd_list.append(param_name)
            if param_name == "--eval":
                cmd_list.append("{0}".format(escape_param(param_value)))
            else:
                cmd_list.append(param_value)
        elif is_bool is True:
            cmd_list.append(param_name)
    return cmd_list


def extract_json_document(output):
    """
    This is for specific type of mongo shell return data in the format SomeText()
    https://github.com/ansible-collections/community.mongodb/issues/436
    i.e.

    """
    output = output.strip()
    if re.match(r"^[a-zA-Z].*\(", output) and output.endswith(')'):
        first_bracket = output.find('{')
        last_bracket = output.rfind('}')
        if first_bracket > 0 and last_bracket > 0:
            tmp = output[first_bracket:last_bracket + 1]
            tmp = tmp.replace('\n', '')
            tmp = tmp.replace('\t', '')
            if tmp is not None:
                output = tmp
    return output


def transform_output(output, transform_type, split_char):
    output = extract_json_document(output)
    if transform_type == "auto":  # determine what transform_type to perform
        if output.strip().startswith("{") or output.strip().startswith("["):
            transform_type = "json"
        elif isinstance(output.strip().split(None), list):  # Splits on whitespace
            transform_type = "split"
            split_char = None
        elif isinstance(output.strip().split(","), list):
            transform_type = "split"
            split_char = ","
        elif isinstance(output.strip().split(" "), list):
            transform_type = "split"
            split_char = " "
        elif isinstance(output.strip().split("|"), list):
            transform_type = "split"
            split_char = "|"
        elif isinstance(output.strip().split("\t"), list):
            transform_type = "split"
            split_char = "\t"
        else:
            transform_type = "raw"
    if transform_type == "json":
        try:
            output = json.loads(output)
        except json.decoder.JSONDecodeError:
            # Strip Extended JSON stuff like:
            # "_id": ObjectId("58f56171ee9d4bd5e610d6b7"),
            # "count": NumberLong(999),
            output = re.sub(r'\:\s*\S+\s*\(\s*(\S+)\s*\)', r':\1', output)
            try:
                output = json.dumps(output, separators=(',', ':'))
                doc = json.loads(output)
            except json.decoder.JSONDecodeError as excep:
                raise excep
    elif transform_type == "split":
        output = output.strip().split(split_char)
    elif transform_type == "raw":
        output = output.strip()
    return output


def get_hash_value(module):
    '''
    Returns the hash value of either the provided file or eval command
    '''
    hash_value = None
    try:
        import hashlib
    except ImportError as excep:
        module.fail_json(msg="Unable to import hashlib: {0}".format(excep.message))
    if module.params['file'] is not None:
        hash_value = hashlib.md5(module.params['file'].encode('utf-8')).hexdigest()
    else:
        hash_value = hashlib.md5(module.params['eval'].encode('utf-8')).hexdigest()
    return hash_value


def touch(fname, times=None):
    with open(fname, 'a'):
        os.utime(fname, times)


def detect_if_cmd_exist(cmd="mongosh"):
    path = os.getenv('PATH')
    for folder in path.split(os.path.pathsep):
        mongoCmd = os.path.join(folder, cmd)
        if os.path.exists(mongoCmd) and os.access(mongoCmd, os.X_OK):
            return True
    return False
