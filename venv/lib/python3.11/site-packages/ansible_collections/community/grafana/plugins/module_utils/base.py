# -*- coding: utf-8 -*-
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright: (c) 2019, Rémi REY (@rrey)

from __future__ import absolute_import, division, print_function
from ansible.module_utils.urls import url_argument_spec

__metaclass__ = type


def clean_url(url):
    return url.rstrip("/")


def grafana_argument_spec():
    argument_spec = url_argument_spec()

    del argument_spec["force"]
    del argument_spec["force_basic_auth"]
    del argument_spec["http_agent"]
    # Avoid sanity error with devel
    if "use_gssapi" in argument_spec:
        del argument_spec["use_gssapi"]

    argument_spec.update(
        state=dict(choices=["present", "absent"], default="present"),
        url=dict(aliases=["grafana_url"], type="str", required=True),
        grafana_api_key=dict(type="str", no_log=True),
        url_username=dict(aliases=["grafana_user"], default="admin"),
        url_password=dict(aliases=["grafana_password"], default="admin", no_log=True),
    )
    return argument_spec


def grafana_required_together():
    return [["url_username", "url_password"]]


def grafana_mutually_exclusive():
    return [["url_username", "grafana_api_key"]]


def parse_grafana_version(version):
    version, sep, build_meta = version.partition("+")
    version, sep, pre_release = version.partition("-")
    major, minor, rev = version.split(".")
    return {
        "major": int(major),
        "minor": int(minor),
        "rev": int(rev),
        "pre_release": pre_release,
        "build_meta": build_meta,
    }
