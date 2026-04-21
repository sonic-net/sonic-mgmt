# Copyright (c) 2013, Romeo Theriault <romeot () hawaii.edu>
# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import os
import shutil
import tempfile
import traceback
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ModuleFailException,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover


def read_file(fn: str | os.PathLike) -> bytes:
    try:
        with open(fn, "rb") as f:
            return f.read()
    except Exception as e:
        raise ModuleFailException(f'Error while reading file "{fn}": {e}') from e


# This function was adapted from an earlier version of https://github.com/ansible/ansible/blob/devel/lib/ansible/modules/uri.py
def write_file(
    *, module: AnsibleModule, dest: str | os.PathLike[str], content: bytes
) -> bool:
    """
    Write content to destination file dest, only if the content
    has changed.
    """
    changed = False
    # create a tempfile
    fd, tmpsrc = tempfile.mkstemp(text=False)
    f = os.fdopen(fd, "wb")
    try:
        f.write(content)
    except Exception as err:
        try:
            f.close()
        except Exception:
            pass
        os.remove(tmpsrc)
        raise ModuleFailException(
            f"failed to create temporary content file: {err}",
            exception=traceback.format_exc(),
        ) from err
    f.close()
    checksum_src = None
    checksum_dest = None
    # raise an error if there is no tmpsrc file
    if not os.path.exists(tmpsrc):
        try:
            os.remove(tmpsrc)
        except Exception:
            pass
        raise ModuleFailException(f"Source {tmpsrc} does not exist")
    if not os.access(tmpsrc, os.R_OK):
        os.remove(tmpsrc)
        raise ModuleFailException(f"Source {tmpsrc} not readable")
    checksum_src = module.sha1(tmpsrc)
    # check if there is no dest file
    if os.path.exists(dest):
        # raise an error if copy has no permission on dest
        if not os.access(dest, os.W_OK):
            os.remove(tmpsrc)
            raise ModuleFailException(f"Destination {dest} not writable")
        if not os.access(dest, os.R_OK):
            os.remove(tmpsrc)
            raise ModuleFailException(f"Destination {dest} not readable")
        checksum_dest = module.sha1(str(dest))
    else:
        dirname = os.path.dirname(dest) or "."
        if not os.access(dirname, os.W_OK):
            os.remove(tmpsrc)
            raise ModuleFailException(f"Destination dir {dirname} not writable")
    if checksum_src != checksum_dest:
        try:
            shutil.copyfile(tmpsrc, dest)
            changed = True
        except Exception as err:
            os.remove(tmpsrc)
            raise ModuleFailException(
                f"failed to copy {tmpsrc} to {dest}: {err}",
                exception=traceback.format_exc(),
            ) from err
    os.remove(tmpsrc)
    return changed


__all__ = ("read_file", "write_file")
