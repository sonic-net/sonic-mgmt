# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import time


class BreakRetry(Exception):
    def __init__(self, message="break", detail=None):
        super().__init__(message)
        self.detail = detail


def retry_until(func, max_time_to_wait, interval_seconds, *args, **kwargs):
    deadline = time.time() + float(max_time_to_wait)
    attempts = 0
    last_detail = None
    last_error = None

    while True:
        attempts += 1
        try:
            ok, detail = func(*args, **kwargs)
        except BreakRetry as br:
            return {
                "ok": False,
                "attempts": attempts,
                "error": str(br) or "break",
                "detail": (br.detail if br.detail is not None else last_detail),
            }
        if ok:
            return {"ok": True, "attempts": attempts, "error": None, "detail": detail}

        last_detail = detail
        last_error = detail if isinstance(detail, str) else None

        if time.time() >= deadline:
            return {"ok": False, "attempts": attempts, "error": (last_error or "timeout"), "detail": last_detail}

        time.sleep(float(interval_seconds))
