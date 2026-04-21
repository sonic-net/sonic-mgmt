#!/usr/bin/python

# 2020 Rhys Campbell <rhys.james.campbell@googlemail.com>
# https://github.com/rhysmeister
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


DOCUMENTATION = '''
---
module: mongodb_shell
author: Rhys Campbell (@rhysmeister)
version_added: "1.1.0"
short_description: Run commands via the MongoDB shell.
requirements:
  - mongosh
description:
    - Run commands via the MongoDB shell.
    - Commands provided with the eval parameter or included in a Javascript file.
    - Attempts to parse returned data into a format that Ansible can use.
    - Module uses the mongosh shell by default.
    - Support for mongo is depreciated.

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  mongo_cmd:
    description:
      - The MongoDB shell command.
      - auto - Automatically detect which MongoDB shell command used. Use "mongosh" if available, else use "mongo" command.
      - mongo - This should still work for most cases but you might have problems with json parsinf. Use transform_type of 'raw' is you encounter problems.
    type: str
    default: "mongosh"
  db:
    description:
      - The database to run commands against
    type: str
    required: false
    default: "test"
  file:
    description:
      - Path to a file containing MongoDB commands.
    type: str
  eval:
    description:
      - A MongoDB command to run.
    type: str
  nodb:
    description:
      - Specify a non-default encoding for output.
    type: bool
    default: false
  norc:
    description:
      - Prevents the shell from sourcing and evaluating ~/.mongorc.js on start up.
    type: bool
    default: false
  quiet:
    description:
      - Silences output from the shell during the connection process..
    type: bool
    default: true
  debug:
    description:
      - show additional debug info.
    type: bool
    default: false
  transform:
    description:
      - Transform the output returned to the user.
      - auto - Attempt to automatically decide the best tranformation.
      - split - Split output on a character.
      - json - parse as json.
      - raw - Return the raw output.
    type: str
    choices:
      - "auto"
      - "split"
      - "json"
      - "raw"
    default: "auto"
  split_char:
    description:
      - Used by the split action in the transform stage.
    type: str
    default: " "
  stringify:
    description:
      - Wraps the command in eval in JSON.stringify(<js cmd>) (mongo) or EJSON.stringify(<js cmd>) (mongosh).
      - Useful for escaping documents that are returned in Extended JSON format.
      - Automatically set to false when using mongo.
      - Automatically set to true when using mongosh.
      - Set explicitly to override automatic selection.
    type: bool
    default: null
  additional_args:
    description:
      - Additional arguments to supply to the mongo command.
      - Supply as key-value pairs.
      - If the parameter is a valueless flag supply an empty string as the value.
    type: raw
  idempotent:
    description:
      - Provides a form of pseudo-idempotency to the module.
      - We perform a hash calculation on the contents of the eval key or the file name provided in the file key.
      - When the command is first execute a filed called <hash>.success will be created.
      - The module will not rerun the command if this file exists and idempotent is set to true.
    type: bool
    default: false
  omit:
    description:
      - Parameter to omit from the command line.
      - This should match the parameter name that the MongoDB shell accepts not the module name.
    type: list
    elements: str
    default: []
'''

EXAMPLES = '''
- name: Run the listDatabases command
  community.mongodb.mongodb_shell:
    login_user: user
    login_password: secret
    eval: "db.adminCommand('listDatabases')"

- name: List collections and stringify the output
  community.mongodb.mongodb_shell:
    login_user: user
    login_password: secret
    eval: "db.adminCommand('listCollections')"
    stringify: yes

- name: Run the showBuiltinRoles command
  community.mongodb.mongodb_shell:
    login_user: user
    login_password: secret
    eval: "db.getRoles({showBuiltinRoles: true})"

- name: Run a js file containing MongoDB commands with pseudo-idempotency
  community.mongodb.mongodb_shell:
    login_user: user
    login_password: secret
    file: "/path/to/mongo/file.js"
    idempotent: yes

- name: Provide a couple of additional cmd args
  community.mongodb.mongodb_shell:
    login_user: user
    login_password: secret
    eval: "db.adminCommand('listDatabases')"
    additional_args:
      verbose: True
      networkMessageCompressors: "snappy"
'''

RETURN = '''
file:
  description: JS file that was executed successfully.
  returned: When a js file is used.
  type: str
msg:
  description: A message indicating what has happened.
  returned: always
  type: str
transformed_output:
  description: Output from the mongo command. We attempt to parse this into a list or json where possible.
  returned: on success
  type: list
changed:
  description: Change status.
  returned: always
  type: bool
failed:
  description: Something went wrong.
  returned: on failure
  type: bool
out:
  description: Raw stdout from mongo.
  returned: when debug is set to true
  type: str
err:
  description: Raw stderr from mongo.
  returned: when debug is set to true
  type: str
rc:
  description: Return code from mongo.
  returned: when debug is set to true
  type: int
'''

from ansible.module_utils.basic import AnsibleModule
import os
__metaclass__ = type

from ansible_collections.community.mongodb.plugins.module_utils.mongodb_common import (
    load_mongocnf, mongodb_common_argument_spec
)

from ansible_collections.community.mongodb.plugins.module_utils.mongodb_shell import (
    add_arg_to_cmd,
    transform_output,
    get_hash_value,
    touch,
    detect_if_cmd_exist
)


def main():
    argument_spec = mongodb_common_argument_spec(ssl_options=True)
    argument_spec.update(
        mongo_cmd=dict(type='str', default="mongosh"),
        file=dict(type='str', required=False),
        eval=dict(type='str', required=False),
        db=dict(type='str', required=False, default="test"),
        nodb=dict(type='bool', required=False, default=False),
        norc=dict(type='bool', required=False, default=False),
        quiet=dict(type='bool', required=False, default=True),
        debug=dict(type='bool', required=False, default=False),
        transform=dict(type='str', choices=["auto", "split", "json", "raw"], default="auto"),
        split_char=dict(type='str', default=" "),
        stringify=dict(type='bool', default=None),
        additional_args=dict(type='raw'),
        idempotent=dict(type='bool', default=False),
        omit=dict(type='list', elements='str', default=[]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[['login_user', 'login_password']],
        mutually_exclusive=[["eval", "file"]]
    )

    if module.params['mongo_cmd'] == "auto":
        module.params['mongo_cmd'] = "mongosh" if detect_if_cmd_exist() else "mongo"

    if module.params['mongo_cmd'] == "mongo" and module.params['stringify'] is None:
        module.params['stringify'] = False
    elif module.params['mongo_cmd'] == "mongosh" and module.params['stringify'] is None:
        module.params['stringify'] = True

    args = [
        module.params['mongo_cmd'],
        module.params['db']
    ]

    hash_value = get_hash_value(module)

    if module.params['idempotent']:
        if os.path.isfile("{0}.success".format(hash_value)):
            module.exit_json(changed=False,
                             msg="The file {0}.success was found meaning this "
                             "command has already successfully executed "
                             "on this MongoDB host.".format(hash_value))

    if not module.params['file']:
        if module.params['eval'].startswith("show "):
            msg = "You cannot use any shell helper (e.g. use <dbname>, show dbs, etc.)"\
                  " inside the eval parameter because they are not valid JavaScript."
            module.fail_json(msg=msg)
        if module.params['stringify']:
            if module.params['mongo_cmd'] != "mongosh":
                module.params['eval'] = "JSON.stringify({0})".format(module.params['eval'])
            else:
                module.params['eval'] = "EJSON.stringify({0})".format(module.params['eval'])

    omit = module.params['omit']

    username = module.params['login_user']
    password = module.params['login_password']

    credentials = load_mongocnf()
    if credentials:
        if not username:
            username = credentials['user']
        if not password:
            password = credentials['password']

    tmp_con_options = ""
    # TODO This could be refactored into a function
    if module.params['connection_options']:
        tmp_con_options = "?"
        for item in module.params['connection_options']:
            # could be a list of dicts or a list of strings
            if isinstance(item, dict):
                for key, value in item.items():
                    tmp_con_options += "{0}={1}&".format(key, value)
            elif isinstance(item, str) and "=" in item:
                tmp_con_options += "{0}&".format(item)
            else:
                raise ValueError("Invalid value supplied in connection_options: {0} .".format(str(item)))
        # We need to use a different connection format when conn params are supplied
        tmp_db = args[1]
        tmp_con_options = tmp_con_options[:-1]
        args[1] = "mongodb://{0}:{1}/{2}{3}".format(module.params['login_host'],
                                                    module.params['login_port'],
                                                    tmp_db,
                                                    tmp_con_options)
    else:
        args = add_arg_to_cmd(args, "--host", module.params['login_host'], omit=omit)
        args = add_arg_to_cmd(args, "--port", module.params['login_port'], omit=omit)
    args = add_arg_to_cmd(args, "--username", username, omit=omit)
    args = add_arg_to_cmd(args, "--password", password, omit=omit)
    args = add_arg_to_cmd(args, "--authenticationDatabase", module.params['login_database'], omit=omit)
    args = add_arg_to_cmd(args, "--authenticationMechanism", module.params['auth_mechanism'], omit=omit)
    args = add_arg_to_cmd(args, "--eval", module.params['eval'], omit=omit)
    args = add_arg_to_cmd(args, "--nodb", None, module.params['nodb'], omit=omit)
    args = add_arg_to_cmd(args, "--norc", None, module.params['norc'], omit=omit)
    args = add_arg_to_cmd(args, "--quiet", None, module.params['quiet'], omit=omit)

    args = add_arg_to_cmd(args, "--tls", None, module.params['ssl'], omit=omit)
    args = add_arg_to_cmd(args, "--tlsAllowInvalidCertificates", None, module.params['ssl_cert_reqs'] in ('CERT_NONE', 'CERT_OPTIONAL'), omit=omit)
    args = add_arg_to_cmd(args, "--tlsCAFile", module.params['ssl_ca_certs'], omit=omit)
    args = add_arg_to_cmd(args, "--tlsCRLFile", module.params['ssl_crlfile'], omit=omit)
    args = add_arg_to_cmd(args, "--tlsCertificateKeyFile", module.params['ssl_keyfile'], omit=omit)
    args = add_arg_to_cmd(args, "--tlsCertificateKeyFilePassword", module.params['ssl_pem_passphrase'], omit=omit)

    additional_args = module.params['additional_args']
    if additional_args is not None:
        for key, value in additional_args.items():
            if isinstance(value, bool):
                args.append(" --{0}".format(key))
            elif isinstance(value, str) or isinstance(value, int):
                args.append(" --{0} {1}".format(key, value))
    if module.params['file']:
        args.append(module.params['file'])

    rc = None
    out = ''
    err = ''
    result = {}
    cmd = " ".join(str(item) for item in args)

    (rc, out, err) = module.run_command(cmd, check_rc=False)

    if module.params['debug']:
        result['out'] = out
        result['err'] = err
        result['rc'] = rc
        result['cmd'] = cmd

    if rc != 0:
        if err is None or err == "":
            err = out
        module.fail_json(msg=err.strip(), **result)
    else:
        result['changed'] = True
        if module.params['idempotent']:
            touch("{0}.success".format(hash_value))
        try:
            output = transform_output(out,
                                      module.params['transform'],
                                      module.params['split_char'])
            result['transformed_output'] = output
            result['msg'] = "transform type was {0}".format(module.params['transform'])
            if module.params['file'] is not None:
                result['file'] = module.params['file']
        except Exception as excep:
            result['msg'] = "Error tranforming output: {0}".format(str(excep))
            result['transformed_output'] = None

    module.exit_json(**result)


if __name__ == '__main__':
    main()
