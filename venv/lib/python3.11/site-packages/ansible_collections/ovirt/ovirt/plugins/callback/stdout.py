#!/usr/bin/python

# -*- coding: utf-8 -*-

# Copyright: (c) 2016, Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

# Not only visible to ansible-doc, it also 'declares' the options the plugin
# requires and how to configure them.
# TODO Fix DOCUMENTATION to pass the ansible-test validate-modules
DOCUMENTATION = '''
name: stdout
type: aggregate
short_description: Output the log of ansible
version_added: "2.0.0"
description:
 - This callback output the log of ansible play tasks.
'''

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    """
    This callback module output the information with a specific style.
    """
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'stdout'

    # only needed if you ship it and don't want to enable by default
    CALLBACK_NEEDS_WHITELIST = False

    def __init__(self):

        # make sure the expected objects are present, calling the base's
        # __init__
        super(CallbackModule, self).__init__()

    def runner_on_failed(self, host, res, ignore_errors=False):
        self._display.display('FAILED: %s %s' % (host, res))

    def runner_on_ok(self, host, res):
        self._display.display('OK: %s %s' % (host, res))

    def runner_on_skipped(self, host, item=None):
        self._display.display('SKIPPED: %s' % host)

    def runner_on_unreachable(self, host, res):
        self._display.display('UNREACHABLE: %s %s' % (host, res))

    def runner_on_async_failed(self, host, res, jid):
        self._display.display('ASYNC_FAILED: %s %s %s' % (host, res, jid))

    def playbook_on_import_for_host(self, host, imported_file):
        self._display.display('IMPORTED: %s %s' % (host, imported_file))

    def playbook_on_not_import_for_host(self, host, missing_file):
        self._display.display('NOTIMPORTED: %s %s' % (host, missing_file))
