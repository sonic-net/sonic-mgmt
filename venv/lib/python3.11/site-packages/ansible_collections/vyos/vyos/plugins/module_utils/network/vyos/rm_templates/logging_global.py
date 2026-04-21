# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Logging_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def tmplt_params(config_data):
    def templt_common(val, tmplt):
        if val.get("facility"):
            tmplt += " facility {facility}".format(facility=val["facility"])
        if val.get("severity"):
            tmplt += " level {level}".format(level=val["severity"])
        elif val.get("protocol"):
            tmplt += " protocol {protocol}".format(protocol=val["protocol"])
        return tmplt

    tmplt = ""
    if config_data.get("global_params"):
        val = config_data.get("global_params")
        if not val.get("archive"):
            tmplt += "system syslog global"
        tmplt = templt_common(val.get("facilities"), tmplt)
    elif config_data.get("console"):
        val = config_data.get("console")
        tmplt += "system syslog console"
        tmplt = templt_common(val.get("facilities"), tmplt)
    elif config_data.get("users"):
        val = config_data.get("users")
        if val.get("username") and not val.get("archive"):
            tmplt += "system syslog user {username}".format(username=val["username"])
        if val.get("facilities"):
            tmplt = templt_common(val.get("facilities"), tmplt)
    elif config_data.get("hosts"):
        val = config_data.get("hosts")
        if (
            val.get("hostname")
            and not val.get("archive")
            and not val.get("port")
            and not val.get("protocol")
        ):
            tmplt += "system syslog host {hostname}".format(hostname=val["hostname"])
        if val.get("facilities"):
            tmplt = templt_common(val.get("facilities"), tmplt)
    elif config_data.get("files"):
        val = config_data.get("files")
        if val.get("path") and not val.get("archive"):
            tmplt += "system syslog file {path}".format(path=val["path"])
        if val.get("facilities"):
            tmplt = templt_common(val.get("facilities"), tmplt)
    return tmplt


class Logging_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        prefix = {"set": "set", "remove": "delete"}
        super(Logging_globalTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            prefix=prefix,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "syslog.state",
            "getval": re.compile(
                r"""
                ^set\ssystem
                (\s(?P<syslog>syslog))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog",
            "result": {
                "syslog": {
                    "state": "{{ 'enabled' if syslog is defined else 'disabled' }}",
                },
            },
        },
        {
            "name": "console.facilities",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sconsole\sfacility
                (\s(?P<facility>all|auth|authpriv|cron|daemon|kern|lpr|mail|mark|news|protocols|security|syslog|user|uucp|local[0-7]))?
                (\slevel\s(?P<level>'(emerg|alert|crit|err|warning|notice|info|debug|all)'))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_params,
            "remval": "system syslog console facility {{ console.facilities.facility }}",
            "result": {
                "console": {
                    "facilities": [
                        {
                            "facility": "{{ facility }}",
                            "severity": "{{ level }}",
                        }, ],
                },
            },
        },
        {
            "name": "console.state",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog
                (\s(?P<console>console))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog console",
            "result": {
                "console": {
                    "state": "{{ 'enabled' if console is defined else 'disabled' }}",
                },
            },
        },
        {
            "name": "files.archive.state",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sfile
                (\s(?P<path>\S+))?
                (\s(?P<archive>archive))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog file {{ files.path }} archive",
            "result": {
                "files": {
                    "{{ path }}": {
                        "path": "{{ path }}",
                        "archive": {
                            "state": "{{ 'enabled' if archive is defined else 'disabled' }}",
                        },
                    },
                },
            },
        },
        {
            "name": "files.archive.size",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sfile
                (\s(?P<path>\S+))?
                (\sarchive\ssize\s(?P<size>'(\d+)'))?
                $""", re.VERBOSE,
            ),
            "setval": "system syslog file {{ files.path }} archive size {{ files.archive.size }}",
            "result": {
                "files": {
                    "{{ path }}": {
                        "path": "{{ path }}",
                        "archive": {
                            "size": "{{ size }}",
                        },
                    },
                },
            },
        },
        {
            "name": "files.archive.file_num",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sfile
                (\s(?P<path>\S+))?
                (\sarchive\sfile\s(?P<file_num>'(\d+)'))?
                $""", re.VERBOSE,
            ),
            "setval": "system syslog file {{ files.path }} archive file {{ files.archive.file_num }}",
            "result": {
                "files": {
                    "{{ path }}": {
                        "path": "{{ path }}",
                        "archive": {
                            "file_num": "{{ file_num }}",
                        },
                    },
                },
            },
        },
        {
            "name": "files",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sfile
                (\s(?P<path>\S+))?
                (\sfacility\s(?P<facility>all|auth|authpriv|cron|daemon|kern|lpr|mail|mark|news|protocols|security|syslog|user|uucp|local[0-7]))?
                (\slevel\s(?P<level>'(emerg|alert|crit|err|warning|notice|info|debug|all)'))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_params,
            "remval": "system syslog file{{ (' ' + files.path) if files.path|d('') is defined else '' }}",
            "result": {
                "files": {
                    "{{ path }}": {
                        "path": "{{ path }}",
                        "facilities": [
                            {
                                "facility": "{{ facility }}",
                                "severity": "{{ level }}",
                            }, ],
                    },
                },
            },
        },
        {
            "name": "global_params.state",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog
                (\s(?P<global>global))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog global",
            "result": {
                "global_params": {
                    "state": "{{ 'enabled' if global is defined else 'disabled' }}",
                },
            },
        },
        {
            "name": "global_params.archive.state",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sglobal
                (\s(?P<archive>archive))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog global archive",
            "result": {
                "global_params": {
                    "archive": {
                        "state": "{{ 'enabled' if archive is defined else 'disabled' }}",
                    },
                },
            },
        },
        {
            "name": "global_params.archive.file_num",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sglobal\sarchive\sfile
                (\s(?P<file_num>'(\d+)'))?
                $""", re.VERBOSE,
            ),
            "setval": "system syslog global archive file {{ global_params.archive.file_num }}",
            "result": {
                "global_params": {
                    "archive": {
                        "file_num": "{{ file_num }}",
                    },
                },
            },
        },
        {
            "name": "global_params.archive.size",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sglobal\sarchive\ssize
                (\s(?P<size>'(\d+)'))?
                $""", re.VERBOSE,
            ),
            "setval": "system syslog global archive size {{ global_params.archive.size }}",
            "result": {
                "global_params": {
                    "archive": {
                        "size": "{{ size }}",
                    },
                },
            },
        },
        {
            "name": "global_params.marker_interval",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sglobal\smarker\sinterval
                (\s(?P<marker_interval>'(\d+)'))?
                $""", re.VERBOSE,
            ),
            "setval": "system syslog global marker interval {{ global_params.marker_interval }}",
            "remval": "system syslog global marker",
            "result": {
                "global_params": {
                    "marker_interval": "{{ marker_interval }}",
                },
            },
        },
        {
            "name": "global_params.preserve_fqdn",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sglobal
                (\s(?P<preserve_fqdn>preserve-fqdn))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog global preserve-fqdn",
            "result": {
                "global_params": {
                    "preserve_fqdn": "{{ True if preserve_fqdn is defined }}",
                },
            },
        },
        {
            "name": "global_params.facilities",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\sglobal\sfacility
                (\s(?P<facility>all|auth|authpriv|cron|daemon|kern|lpr|mail|mark|news|protocols|security|syslog|user|uucp|local[0-7]))?
                (\slevel\s(?P<level>'(emerg|alert|crit|err|warning|notice|info|debug|all)'))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_params,
            "remval": "system syslog global facility {{ global_params.facilities.facility }}",
            "result": {
                "global_params": {
                    "facilities": [
                        {
                            "facility": "{{ facility }}",
                            "severity": "{{ level }}",
                        }, ],
                },
            },
        },
        {
            "name": "hosts.port",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\shost
                (\s(?P<hostname>\S+))
                (\sport\s(?P<port>'(\d+)'))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog host {{ hosts.hostname }} port {{ hosts.port }}",
            "result": {
                "hosts": {
                    "{{ hostname }}": {
                        "hostname": "{{ hostname }}",
                        "port": "{{ port }}",
                    },
                },
            },
        },
        {
            "name": "hosts.protocol",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\shost
                (\s(?P<hostname>\S+))
                (\sprotocol\s(?P<protocol>'(udp|tcp)'))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog host {{ hosts.hostname }} protocol {{ hosts.protocol }}",
            "result": {
                "hosts": {
                    "{{ hostname }}": {
                        "hostname": "{{ hostname }}",
                        "protocol": "{{ protocol }}",
                    },
                },
            },
        },
        {
            # Version 1.3 and below
            "name": "hosts.facility.protocol",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\shost
                (\s(?P<hostname>\S+))
                (\sfacility\s(?P<facility>all|auth|authpriv|cron|daemon|kern|lpr|mail|mark|news|protocols|security|syslog|user|uucp|local[0-7]))
                (\sprotocol\s(?P<protocol>'(udp|tcp)'))
                $""", re.VERBOSE,
            ),
            "setval": "system syslog host {{ hosts.hostname }} facility {{ hosts.facility }} protocol {{ hosts.protocol }}",
            "remval": "system syslog host {{ hosts.hostname }} facility {{ hosts.facility }} protocol {{ hosts.protocol }}",
            "result": {
                "hosts": {
                    "{{ hostname }}": {
                        "hostname": "{{ hostname }}",
                        "facilities": [
                            {
                                "facility": "{{ facility }}",
                                "protocol": "{{ protocol }}",
                            }, ],
                    },
                },
            },
        },
        {
            "name": "hosts",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\shost
                (\s(?P<hostname>\S+))
                (\sfacility\s(?P<facility>all|auth|authpriv|cron|daemon|kern|lpr|mail|mark|news|protocols|security|syslog|user|uucp|local[0-7]))
                (\slevel\s(?P<level>'(emerg|alert|crit|err|warning|notice|info|debug|all)'))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_params,
            "remval": "system syslog host {{ hosts.hostname }}",
            "result": {
                "hosts": {
                    "{{ hostname }}": {
                        "hostname": "{{ hostname }}",
                        "facilities": [
                            {
                                "facility": "{{ facility }}",
                                "severity": "{{ level }}",
                            }, ],
                    },
                },
            },
        },
        {
            "name": "users",
            "getval": re.compile(
                r"""
                ^set\ssystem\ssyslog\suser
                (\s(?P<username>\S+))?
                (\sfacility\s(?P<facility>all|auth|authpriv|cron|daemon|kern|lpr|mail|mark|news|protocols|security|syslog|user|uucp|local[0-7]))?
                (\slevel\s(?P<level>'(emerg|alert|crit|err|warning|notice|info|debug|all)'))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_params,
            "remval": "system syslog user {{ users.username }}",
            "result": {
                "users": {
                    "{{ username }}": {
                        "username": "{{ username }}",
                        "facilities": [
                            {
                                "facility": "{{ facility }}",
                                "severity": "{{ level }}",
                            }, ],
                    },
                },
            },
        },
    ]
    # fmt: on
