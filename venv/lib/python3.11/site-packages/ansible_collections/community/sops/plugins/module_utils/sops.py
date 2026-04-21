# Copyright (c), Edoardo Tenani <e.tenani@arduino.cc>, 2018-2020
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import collections
import json
import os
import re

from ansible.module_utils.common.text.converters import to_text, to_native

# Since this is used both by plugins and modules, we need subprocess in case the `module` parameter is not used
from subprocess import Popen, PIPE


# From https://github.com/getsops/sops/blob/master/cmd/sops/codes/codes.go
# Should be manually updated
SOPS_ERROR_CODES = {
    1: "ErrorGeneric",
    2: "CouldNotReadInputFile",
    3: "CouldNotWriteOutputFile",
    4: "ErrorDumpingTree",
    5: "ErrorReadingConfig",
    6: "ErrorInvalidKMSEncryptionContextFormat",
    7: "ErrorInvalidSetFormat",
    8: "ErrorConflictingParameters",
    21: "ErrorEncryptingMac",
    23: "ErrorEncryptingTree",
    24: "ErrorDecryptingMac",
    25: "ErrorDecryptingTree",
    49: "CannotChangeKeysFromNonExistentFile",
    51: "MacMismatch",
    52: "MacNotFound",
    61: "ConfigFileNotFound",
    85: "KeyboardInterrupt",
    91: "InvalidTreePathFormat",
    100: "NoFileSpecified",
    128: "CouldNotRetrieveKey",
    111: "NoEncryptionKeyFound",
    200: "FileHasNotBeenModified",
    201: "NoEditorFound",
    202: "FailedToCompareVersions",
    203: "FileAlreadyEncrypted"
}

_SOPS_VERSION = re.compile(r'^sops ([0-9]+)\.([0-9]+)\.([0-9]+)')


def _add_argument(arguments_pre, arguments_post, *args, **kwargs):
    pre = kwargs.pop('pre', False)
    (arguments_pre if pre else arguments_post).extend(args)


def _create_single_arg(argument_name, pre=False):
    def f(value, arguments_pre, arguments_post, env, version):
        _add_argument(arguments_pre, arguments_post, argument_name, to_native(value), pre=pre)

    return f


def _create_comma_separated(argument_name, pre=False):
    def f(value, arguments_pre, arguments_post, env, version):
        value = ','.join([to_native(v) for v in value])
        _add_argument(arguments_pre, arguments_post, argument_name, value, pre=pre)

    return f


def _create_repeated(argument_name, pre=False):
    def f(value, arguments_pre, arguments_post, env, version):
        for v in value:
            _add_argument(arguments_pre, arguments_post, argument_name, to_native(v), pre=pre)

    return f


def _create_boolean(argument_name, pre=False, invert=False):
    def f(value, arguments_pre, arguments_post, env, version):
        if value ^ invert:
            _add_argument(arguments_pre, arguments_post, argument_name, pre=pre)

    return f


def _create_env_variable(argument_name):
    def f(value, arguments_pre, arguments_post, env, version):
        env[argument_name] = value

    return f


GENERAL_OPTIONS = {
    'age_key': _create_env_variable('SOPS_AGE_KEY'),
    'age_keyfile': _create_env_variable('SOPS_AGE_KEY_FILE'),
    'age_ssh_private_keyfile': _create_env_variable('SOPS_AGE_SSH_PRIVATE_KEY_FILE'),
    'aws_profile': _create_single_arg('--aws-profile'),
    'aws_access_key_id': _create_env_variable('AWS_ACCESS_KEY_ID'),
    'aws_secret_access_key': _create_env_variable('AWS_SECRET_ACCESS_KEY'),
    'aws_session_token': _create_env_variable('AWS_SESSION_TOKEN'),
    'config_path': _create_single_arg('--config', pre=True),
    'enable_local_keyservice': _create_boolean('--enable-local-keyservice=false', invert=True),
    'keyservice': _create_repeated('--keyservice'),
}


ENCRYPT_OPTIONS = {
    'age': _create_comma_separated('--age'),
    'kms': _create_comma_separated('--kms'),
    'gcp_kms': _create_comma_separated('--gcp-kms'),
    'azure_kv': _create_comma_separated('--azure-kv'),
    'hc_vault_transit': _create_comma_separated('--hc-vault-transit'),
    'pgp': _create_comma_separated('--pgp'),
    'unencrypted_suffix': _create_single_arg('--unencrypted-suffix'),
    'encrypted_suffix': _create_single_arg('--encrypted-suffix'),
    'unencrypted_regex': _create_single_arg('--unencrypted-regex'),
    'encrypted_regex': _create_single_arg('--encrypted-regex'),
    'encryption_context': _create_comma_separated('--encryption-context'),
    'shamir_secret_sharing_threshold': _create_single_arg('--shamir-secret-sharing-threshold'),
}


class SopsError(Exception):
    ''' Extend Exception class with sops specific information '''

    def __init__(self, filename, exit_code, message, decryption=True, operation=None):
        if operation is None:
            operation = 'decrypt' if decryption else 'encrypt'
        if exit_code in SOPS_ERROR_CODES:
            exception_name = SOPS_ERROR_CODES[exit_code]
            message = "error with file %s: %s exited with code %d: %s" % (
                filename, exception_name, exit_code, to_native(message))
        else:
            message = "could not %s file %s; Unknown sops error code: %s; message: %s" % (
                operation, filename, exit_code, to_native(message))
        super(SopsError, self).__init__(message)


SopsFileStatus = collections.namedtuple('SopsFileStatus', ['encrypted'])


class SopsRunner(object):
    def _add_options(self, command_pre, command_post, env, get_option_value, options):
        if get_option_value is None:
            return
        for option, f in options.items():
            v = get_option_value(option)
            if v is not None:
                f(v, command_pre, command_post, env, self.version)

    def _debug(self, message):
        if self.display:
            self.display.vvvv(message)
        elif self.module:
            self.module.debug(message)

    def _warn(self, message):
        if self.display:
            self.display.warning(message)
        elif self.module:
            self.module.warn(message)

    def __init__(self, binary, module=None, display=None):
        self.binary = binary
        self.module = module
        self.display = display

        self.version = (3, 7, 3)  # if --disable-version-check is not supported, this is version 3.7.3 or older
        self.version_string = '(before 3.8.0)'

        exit_code, output, err = self._run_command([self.binary, '--version', '--disable-version-check'])
        if exit_code == 0:
            m = _SOPS_VERSION.match(output.decode('utf-8'))
            if m:
                self.version = int(m.group(1)), int(m.group(2)), int(m.group(3))
                self.version_string = '%d.%d.%d' % self.version
                self._debug('SOPS version detected as %s' % (self.version, ))
            else:
                self._warn('Cannot extract SOPS version from: %s' % repr(output))
        else:
            self._debug('Cannot detect SOPS version efficiently, likely a version before 3.8.0')

    def _run_command(self, command, env=None, data=None, cwd=None):
        if self.module:
            return self.module.run_command(command, environ_update=env, cwd=cwd, encoding=None, data=data, binary_data=True)

        process = Popen(command, stdin=None if data is None else PIPE, stdout=PIPE, stderr=PIPE, cwd=cwd, env=env)
        output, err = process.communicate(input=data)
        return process.returncode, output, err

    def decrypt(self, encrypted_file, content=None,
                decode_output=True, rstrip=True, input_type=None, output_type=None, get_option_value=None, extract=None):
        # Run sops directly, python module is deprecated
        command = [self.binary]
        command_post = []
        env = os.environ.copy()
        self._add_options(command, command_post, env, get_option_value, GENERAL_OPTIONS)
        if self.version >= (3, 9, 0):
            command.append("decrypt")
        command.extend(command_post)
        if input_type is not None:
            command.extend(["--input-type", input_type])
        if output_type is not None:
            command.extend(["--output-type", output_type])
        if self.version < (3, 9, 0):
            command.append("--decrypt")
        if extract is not None:
            command.extend(["--extract", extract])
        if content is not None:
            encrypted_file = '/dev/stdin'
        command.append(encrypted_file)

        exit_code, output, err = self._run_command(command, env=env, data=content)

        if decode_output:
            # output is binary, we want UTF-8 string
            output = to_text(output, errors='surrogate_or_strict')
            # the process output is the decrypted secret; be cautious

        # sops logs always to stderr, as stdout is used for
        # file content
        if err:
            self._debug(u'Unexpected stderr:\n' + to_text(err, errors='surrogate_or_strict'))

        if exit_code != 0:
            raise SopsError(encrypted_file, exit_code, err, decryption=True)

        if rstrip:
            output = output.rstrip()

        return output

    def encrypt(self, data, cwd=None, input_type=None, output_type=None, filename=None, get_option_value=None):
        # Run sops directly, python module is deprecated
        command = [self.binary]
        command_post = []
        env = os.environ.copy()
        self._add_options(command, command_post, env, get_option_value, GENERAL_OPTIONS)
        self._add_options(command, command_post, env, get_option_value, ENCRYPT_OPTIONS)
        if self.version >= (3, 9, 0):
            command.append("encrypt")
        command.extend(command_post)
        if input_type is not None:
            command.extend(["--input-type", input_type])
        if output_type is not None:
            command.extend(["--output-type", output_type])
        if self.version < (3, 9, 0):
            command.append("--encrypt")
        if self.version >= (3, 9, 0) and filename:
            command.extend(["--filename-override", filename])
        command.append("/dev/stdin")

        exit_code, output, err = self._run_command(command, env=env, data=data, cwd=cwd)

        # sops logs always to stderr, as stdout is used for
        # file content
        if err:
            self._debug(u'Unexpected stderr:\n' + to_text(err, errors='surrogate_or_strict'))

        if exit_code != 0:
            raise SopsError('to stdout', exit_code, err, decryption=False)

        return output

    def has_filestatus(self):
        return self.version >= (3, 9, 0)

    def get_filestatus(self, path):
        command = [self.binary, 'filestatus', path]

        exit_code, output, err = self._run_command(command)

        # sops logs always to stderr, as stdout is used for
        # file content
        if err:
            self._debug(u'Unexpected stderr:\n' + to_text(err, errors='surrogate_or_strict'))

        if exit_code != 0:
            raise SopsError(path, exit_code, err, operation='inspect')

        try:
            result = json.loads(output)
            return SopsFileStatus(result['encrypted'])
        except Exception as exc:
            self._debug(u'Unexpected stdout:\n' + to_text(output, errors='surrogate_or_strict'))
            raise SopsError(path, 0, 'Cannot decode filestatus result: %s' % exc, operation='inspect')


_SOPS_RUNNER_CACHE = dict()


class Sops():
    ''' Utility class to perform sops CLI actions '''

    @staticmethod
    def get_sops_binary(get_option_value):
        cmd = get_option_value('sops_binary') if get_option_value else None
        if cmd is None:
            cmd = 'sops'
        return cmd

    @staticmethod
    def get_sops_runner_from_binary(sops_binary, module=None, display=None):
        candidates = _SOPS_RUNNER_CACHE.get(sops_binary, [])
        for cand_module, cand_runner in candidates:
            if cand_runner is module:
                return cand_runner
        runner = SopsRunner(sops_binary, module=module, display=display)
        candidates.append((module, runner))
        _SOPS_RUNNER_CACHE[sops_binary] = candidates
        return runner

    @staticmethod
    def get_sops_runner_from_options(get_option_value, module=None, display=None):
        return Sops.get_sops_runner_from_binary(Sops.get_sops_binary(get_option_value), module=module, display=display)

    @staticmethod
    def decrypt(encrypted_file, content=None,
                display=None, decode_output=True, rstrip=True, input_type=None, output_type=None, get_option_value=None, module=None, extract=None):
        runner = Sops.get_sops_runner_from_options(get_option_value, module=module, display=display)
        return runner.decrypt(
            encrypted_file,
            content=content,
            decode_output=decode_output,
            rstrip=rstrip,
            input_type=input_type,
            output_type=output_type,
            get_option_value=get_option_value,
            extract=extract,
        )

    @staticmethod
    def encrypt(data, display=None, cwd=None, input_type=None, output_type=None, get_option_value=None, module=None, filename=None):
        runner = Sops.get_sops_runner_from_options(get_option_value, module=module, display=display)
        return runner.encrypt(
            data,
            cwd=cwd,
            input_type=input_type,
            output_type=output_type,
            get_option_value=get_option_value,
            filename=filename,
        )


def get_sops_argument_spec(add_encrypt_specific=False):
    argument_spec = {
        'sops_binary': {
            'type': 'path',
        },
        'age_key': {
            'type': 'str',
            'no_log': True,
        },
        'age_keyfile': {
            'type': 'path',
        },
        'age_ssh_private_keyfile': {
            'type': 'path',
        },
        'aws_profile': {
            'type': 'str',
        },
        'aws_access_key_id': {
            'type': 'str',
        },
        'aws_secret_access_key': {
            'type': 'str',
            'no_log': True,
        },
        'aws_session_token': {
            'type': 'str',
            'no_log': True,
        },
        'config_path': {
            'type': 'path',
        },
        'enable_local_keyservice': {
            'type': 'bool',
            'default': True,
        },
        'keyservice': {
            'type': 'list',
            'elements': 'str',
        },
    }
    if add_encrypt_specific:
        argument_spec.update({
            'age': {
                'type': 'list',
                'elements': 'str',
            },
            'kms': {
                'type': 'list',
                'elements': 'str',
            },
            'gcp_kms': {
                'type': 'list',
                'elements': 'str',
            },
            'azure_kv': {
                'type': 'list',
                'elements': 'str',
            },
            'hc_vault_transit': {
                'type': 'list',
                'elements': 'str',
            },
            'pgp': {
                'type': 'list',
                'elements': 'str',
            },
            'unencrypted_suffix': {
                'type': 'str',
            },
            'encrypted_suffix': {
                'type': 'str',
            },
            'unencrypted_regex': {
                'type': 'str',
            },
            'encrypted_regex': {
                'type': 'str',
            },
            'encryption_context': {
                'type': 'list',
                'elements': 'str',
            },
            'shamir_secret_sharing_threshold': {
                'type': 'int',
                'no_log': False,
            },
        })
    return argument_spec
