# Copyright (c) 2018 Edoardo Tenani <e.tenani@arduino.cc> (@endorama)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
name: sops
author: Edoardo Tenani (@endorama) <e.tenani@arduino.cc>
short_description: Loading SOPS-encrypted vars files
version_added: '0.1.0'
description:
  - Load encrypted YAML files into corresponding groups/hosts in C(group_vars/) and C(host_vars/) directories.
  - Files are encrypted prior to reading, making this plugin an effective companion to P(ansible.builtin.host_group_vars#vars)
    plugin.
  - Files are restricted to V(.sops.yaml), V(.sops.yml), V(.sops.json) extensions, unless configured otherwise with O(valid_extensions).
  - Hidden files are ignored.
options:
  valid_extensions:
    default: [".sops.yml", ".sops.yaml", ".sops.json"]
    description:
      - Check all of these extensions when looking for 'variable' files.
      - These files must be SOPS encrypted YAML or JSON files.
      - By default the plugin will produce errors when encountering files matching these extensions that are not SOPS encrypted.
        This behavior can be controlled with the O(handle_unencrypted_files) option.
    type: list
    elements: string
    ini:
      - key: valid_extensions
        section: community.sops
        version_added: 1.7.0
    env:
      - name: ANSIBLE_VARS_SOPS_PLUGIN_VALID_EXTENSIONS
        version_added: 1.7.0
  stage:
    version_added: 0.2.0
    ini:
      - key: vars_stage
        section: community.sops
    env:
      - name: ANSIBLE_VARS_SOPS_PLUGIN_STAGE
  cache:
    description:
      - Whether to cache decrypted files or not.
      - If the cache is disabled, the files will be decrypted for almost every task. This is very slow!
      - Only disable caching if you modify the variable files during a playbook run and want the updated result to be available
        from the next task on.
      - 'Note that setting O(stage=inventory) has the same effect as setting O(cache=true): the variables will be loaded only
        once (during inventory loading) and the vars plugin will not be called for every task.'
    type: bool
    default: true
    version_added: 0.2.0
    ini:
      - key: vars_cache
        section: community.sops
    env:
      - name: ANSIBLE_VARS_SOPS_PLUGIN_CACHE
  disable_vars_plugin_temporarily:
    description:
      - Temporarily disable this plugin.
      - Useful if ansible-inventory is supposed to be run without decrypting secrets (in AWX for instance).
    type: bool
    default: false
    version_added: 1.3.0
    env:
      - name: SOPS_ANSIBLE_AWX_DISABLE_VARS_PLUGIN_TEMPORARILY
  handle_unencrypted_files:
    description:
      - How to handle files that match the extensions in O(valid_extensions) that are not SOPS encrypted.
      - The default value V(error) will produce an error.
      - The value V(skip) will simply skip these files. This requires SOPS 3.9.0 or later.
      - The value V(warn) will skip these files and emit a warning. This requires SOPS 3.9.0 or later.
      - B(Note) that this will not help if the store SOPS uses cannot parse the file, for example because it is no valid JSON/YAML/...
        file despite its file extension. For extensions other than the default ones SOPS uses the binary store, which tries
        to parse the file as JSON.
    type: string
    choices:
      - skip
      - warn
      - error
    default: error
    version_added: 1.8.0
    ini:
      - key: handle_unencrypted_files
        section: community.sops
    env:
      - name: ANSIBLE_VARS_SOPS_PLUGIN_HANDLE_UNENCRYPTED_FILES
extends_documentation_fragment:
  - ansible.builtin.vars_plugin_staging
  - community.sops.sops
  - community.sops.sops.ansible_env
  - community.sops.sops.ansible_ini
seealso:
  - plugin: community.sops.sops
    plugin_type: lookup
    description: The sops lookup can be used decrypt SOPS-encrypted files.
  - plugin: community.sops.decrypt
    plugin_type: filter
    description: The decrypt filter can be used to decrypt SOPS-encrypted in-memory data.
  - module: community.sops.load_vars
"""

import os
from collections.abc import Sequence, Mapping

from ansible.errors import AnsibleParserError
from ansible.inventory.host import Host
from ansible.inventory.group import Group
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible.plugins.vars import BaseVarsPlugin
from ansible.utils.display import Display
from ansible.utils.vars import combine_vars
from ansible_collections.community.sops.plugins.module_utils.sops import Sops, SopsError

try:
    from ansible.template import trust_as_template as _trust_as_template
    HAS_DATATAGGING = True
except ImportError:
    HAS_DATATAGGING = False


display = Display()

FOUND = {}
DECRYPTED = {}


def _make_safe(value):
    if isinstance(value, str):
        # must come *before* Sequence, as strings are also instances of Sequence
        if HAS_DATATAGGING and isinstance(value, str):
            return _trust_as_template(value)
        return value
    if isinstance(value, Sequence):
        return [_make_safe(v) for v in value]
    if isinstance(value, Mapping):
        return dict((k, _make_safe(v)) for k, v in value.items())
    return value


class VarsModule(BaseVarsPlugin):

    def get_vars(self, loader, path, entities, cache=None):
        ''' parses the inventory file '''

        if not isinstance(entities, list):
            entities = [entities]

        super().get_vars(loader, path, entities)

        def get_option_value(argument_name):
            return self.get_option(argument_name)

        if cache is None:
            cache = self.get_option('cache')

        if self.get_option('disable_vars_plugin_temporarily'):
            return {}

        valid_extensions = self.get_option('valid_extensions')
        handle_unencrypted_files = self.get_option('handle_unencrypted_files')

        data = {}
        for entity in entities:
            if isinstance(entity, Host):
                subdir = 'host_vars'
            elif isinstance(entity, Group):
                subdir = 'group_vars'
            else:
                raise AnsibleParserError("Supplied entity must be Host or Group, got %s instead" % (type(entity)))

            # avoid 'chroot' type inventory hostnames /path/to/chroot
            if not entity.name.startswith(os.path.sep):
                try:
                    found_files = []
                    # load vars
                    b_opath = os.path.realpath(to_bytes(os.path.join(self._basedir, subdir)))
                    opath = to_text(b_opath)
                    key = '%s.%s' % (entity.name, opath)
                    self._display.vvvv("key: %s" % (key))
                    if cache and key in FOUND:
                        found_files = FOUND[key]
                    else:
                        # no need to do much if path does not exist for basedir
                        if os.path.exists(b_opath):
                            if os.path.isdir(b_opath):
                                self._display.debug("\tprocessing dir %s" % opath)
                                # NOTE: iterating without extension allow retrieving files recursively
                                # A filter is then applied by iterating on all results and filtering by
                                # extension.
                                # See:
                                # - https://github.com/ansible-collections/community.sops/pull/6
                                found_files = loader.find_vars_files(opath, entity.name, extensions=valid_extensions, allow_dir=False)
                                found_files.extend([file_path for file_path in loader.find_vars_files(opath, entity.name)
                                                    if any(to_text(file_path).endswith(extension) for extension in valid_extensions)])
                                FOUND[key] = found_files
                            else:
                                self._display.warning("Found %s that is not a directory, skipping: %s" % (subdir, opath))

                    for found in found_files:
                        if cache and found in DECRYPTED:
                            file_content = DECRYPTED[found]
                        else:
                            sops_runner = Sops.get_sops_runner_from_options(get_option_value, display=display)
                            if handle_unencrypted_files != 'error' and not sops_runner.has_filestatus():
                                raise AnsibleParserError(
                                    'Cannot use handle_unencrypted_files=%s with SOPS %s' % (handle_unencrypted_files, sops_runner.version_string)
                                )
                            try:
                                file_content = sops_runner.decrypt(found, get_option_value=get_option_value)
                            except SopsError as exc:
                                skip = False
                                if sops_runner.has_filestatus():
                                    # Check whether sops thinks the file might be encrypted. If it thinks it is not,
                                    # skip it. Otherwise, re-raise the original error
                                    try:
                                        file_status = sops_runner.get_filestatus(found)
                                        if not file_status.encrypted:
                                            if handle_unencrypted_files == 'skip':
                                                self._display.vvvv("SOPS vars plugin: skipping unencrypted file %s" % found)
                                                skip = True
                                            elif handle_unencrypted_files == 'warn':
                                                self._display.warning("SOPS vars plugin: skipping unencrypted file %s" % found)
                                                skip = True
                                            elif handle_unencrypted_files == 'error':
                                                raise AnsibleParserError("SOPS vars plugin: file %s is not encrypted" % found)
                                    except SopsError as status_exc:
                                        # The filestatus operation can fail for example if sops cannot parse the file
                                        # as JSON/YAML. In that case, also re-raise the original error
                                        self._display.warning("SOPS vars plugin: cannot obtain file status of %s: %s" % (found, status_exc))
                                if skip:
                                    continue
                                raise
                            DECRYPTED[found] = file_content
                        new_data = _make_safe(loader.load(file_content))
                        if new_data:  # ignore empty files
                            data = combine_vars(data, new_data)

                except AnsibleParserError:
                    raise
                except SopsError as e:
                    raise AnsibleParserError(to_native(e))
                except Exception as e:
                    raise AnsibleParserError('Unexpected error in the SOPS vars plugin: %s' % to_native(e))

        return data
