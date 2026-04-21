# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleResult(object):
    def __init__(self, changed=False, failed=False, msg="", extras=None):
        self.changed = bool(changed)
        self.failed = bool(failed)
        self.msg = msg or ""
        self.extras = dict(extras) if extras else {}

    @classmethod
    def ok(cls, msg="", changed=False, **extras):
        return cls(changed=changed, failed=False, msg=msg, extras=extras)

    @classmethod
    def error(cls, msg, **extras):
        return cls(changed=False, failed=True, msg=msg, extras=extras)

    def to_ansible(self):
        data = dict(changed=self.changed, msg=self.msg)
        if self.failed:
            data["failed"] = True
        if self.extras:
            data.update(self.extras)
        return data
