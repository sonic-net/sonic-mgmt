# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Bgp_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_confederation_peers(config_data):
    cmds = []
    base_cmd = "bgp confederation peers "
    peers = config_data.get("bgp", {}).get("confederation", {}).get("peers")
    if peers:
        for peer in peers:
            cmds.append(base_cmd + str(peer))
    return cmds


def _templ_local_as(config_data):
    conf = config_data.get("local_as", {})
    command = ""
    if conf.get("value"):
        command = "local-as " + str(conf.get("value", {}))
    if "no_prepend" in conf:
        if "replace_as" in conf.get("no_prepend", {}):
            if "dual_as" in conf.get("no_prepend", {}).get("replace_as", {}):
                command += " no-prepend replace-as dual-as"
            elif "set" in conf.get("no_prepend", {}).get("replace_as", {}):
                command += " no-prepend replace-as"
        elif "set" in conf.get("no_prepend", {}):
            command += " no-prepend"
    return command


class Bgp_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Bgp_globalTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "router",
            "getval": re.compile(
                r"""
                ^router\s
                bgp
                \s(?P<as_num>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "router bgp {{ as_number }}",
            "compval": "as_number",
            "result": {"as_number": "{{ as_num }}"},
            "shared": True,
        },
        {
            "name": "vrf",
            "getval": re.compile(
                r"""
                \s+vrf
                \s(?P<vrf>\S+)$""",
                re.VERBOSE,
            ),
            "setval": "vrf {{ vrf }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "vrf": "{{ vrf }}",
                    },
                },
            },
            "shared": True,
        },

        {
            "name": "bfd_minimum_interval",
            "getval": re.compile(
                r"""
                \s+bfd\s(?P<min_interval>minimum-interval\s\d+)
                $""", re.VERBOSE,
            ),
            "compval": "bfd.minimum_interval",
            "setval": "bfd minimum-interval {{bfd.minimum_interval}}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bfd": {"minimum_interval": "{{ min_interval.split(" ")[1] }}"},
                    },
                },
            },
        },
        {
            "name": "bfd_multiplier",
            "getval": re.compile(
                r"""
                \s+bfd\s(?P<multiplier>multiplier\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bfd multiplier {{bfd.multiplier}}",
            "compval": "bfd.multiplier",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bfd": {"multiplier": "{{multiplier.split(" ")[1]}}"},
                    },
                },
            },
        },
        {
            "name": "bgp_as_path_loopcheck",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<loopcheck>as-path-loopcheck)
                $""", re.VERBOSE,
            ),
            "setval": "bgp as-path-loopcheck",
            "compval": "bgp.as_path_loopcheck",
            "result": {
                "bgp": {
                    "as_path_loopcheck": "{{ True if loopcheck is defined }}",
                },
            },
        },
        {
            "name": "bgp_auto_policy_soft_reset",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<auto_policy_soft_reset_disable>auto-policy-soft-reset\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "bgp auto-policy-soft-reset disable",
            "compval": "bgp.auto_policy_soft_reset",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "auto_policy_soft_reset": {
                                "disable": "{{True if auto_policy_soft_reset_disable is defined}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_cluster_id",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<cluster_id>cluster-id\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp cluster-id {{bgp.cluster_id}}",
            "compval": "bgp.cluster_id",
            "result": {
                "bgp": {
                    "cluster_id": "{{cluster_id.split(" ")[1]}}",
                },
            },
        },
        {
            "name": "bgp_default_local_preference",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<default_local_pref>default\slocal-preference\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp default local-preference {{bgp.default.local_preference}}",
            "compval": "bgp.default.local-preference",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "default": {
                                "local_preference": "{{default_local_pref.split(" ")[2] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_enforce_first_as_disable",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<enforce_first_as_disable>enforce-first-as\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "bgp enforce-first-as disable",
            "compval": "bgp.enforce_first_as.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "enforce_first_as": {
                                "disable": "{{ True if enforce_first_as_disable is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_fast_external_fallover_disable",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<fast_external_fallover_disable>fast-external-fallover\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "bgp fast-external-fallover disable",
            "compval": "bgp.fast_external_fallover.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "fast_external_fallover": {
                                "disable": "{{True if fast_external_fallover_disable is defined}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_install_diversion",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<install_diversion>install\sdiversion)
                $""", re.VERBOSE,
            ),
            "setval": "bgp install diversion",
            "compval": "bgp.install.diversion",
            "result": {
                "bgp": {
                    "install": {
                        "diversion": "{{True if install_diversion is defined}}",
                    },
                },
            },
        },
        {
            "name": "bgp_max_neighbors",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<max_neighbors>maximum\sneighbor\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp maximum neighbor {{bgp.maximum.neighbor}}",
            "compval": "bgp.maximum.neighbor",
            "result": {
                "bgp": {
                    "maximum":
                        {
                            "neighbor": "{{max_neighbors.split(" ")[2] }}",
                        },
                },
            },
        },
        {
            "name": "bgp_redistribute_internal",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<redistribute_internal>redistribute-internal)
                $""", re.VERBOSE,
            ),
            "setval": "bgp redistribute-internal",
            "compval": "bgp.redistribute_internal",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "redistribute_internal": "{{ True if redistribute_internal is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_router_id",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<router_id>router-id\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp router-id {{ bgp.router_id }}",
            "compval": "bgp.router_id",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "router_id": "{{router_id.split(" ")[1]}}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_scan_time",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<scan_time>scan-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp scan-time {{ bgp.scan_time }}",
            "compval": "bgp.scan_time",
            "result": {
                "bgp": {
                    "scan_time": "{{scan_time.split(" ")[1]}}",
                },
            },
        },
        {
            "name": "bgp_unsafe_ebgp_policy",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<unsafe_ebgp_policy>unsafe-ebgp-policy)
                $""", re.VERBOSE,
            ),
            "setval": "bgp unsafe-ebgp-policy",
            "compval": "bgp.unsafe_ebgp_policy",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "unsafe_ebgp_policy": "{{ True if unsafe_ebgp_policy is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_update_delay",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<update_delay>update-delay\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp update-delay {{ bgp.update_delay }}",
            "compval": "bgp.update_delay",
            "result": {
                "bgp": {
                    "update_delay": "{{update_delay.split(" ")[1]}}",

                },
            },
        },
        {
            "name": "bgp_bestpath_aigp",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<bestpath_aigp_ignore>bestpath\saigp\signore)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath aigp ignore",
            "compval": "bgp.bestpath.aigp.ignore",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "aigp": {
                                    "ignore": "{{ True if bestpath_aigp_ignore is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_as_path_ignore",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<as_path_ignore>bestpath\sas-path\signore)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath as-path ignore",
            "compval": "bgp.bestpath.as_path.ignore",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "as_path": {
                                    "ignore": "{{ True if as_path_ignore is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_as_path_multipath_relax",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<as_path_multipath_relax>bestpath\sas-path\smultipath-relax)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath as-path multipath-relax",
            "compval": "bgp.bestpath.as_path.multipath_relax",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "as_path": {
                                    "multipath_relax": "{{ True if as_path_multipath_relax is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_med_always",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<always>bestpath\smed\salways)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath med always",
            "compval": "bgp.bestpath.med.always",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "med": {
                                    "always": "{{ True if always is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_med_confed",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<confed>bestpath\smed\sconfed)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath med confed",
            "compval": "bgp.bestpath.med.confed",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "med": {
                                    "confed": "{{ True if confed is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_med_missing_as_worst",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<missing_as_worst>bestpath\smed\smissing-as-worst)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath med missing-as-worst)",
            "compval": "bgp.bestpath.med.missing_as_worst",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "med": {
                                    "missing_as_worst": "{{ True if missing_as_worst is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_compare_routerid",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<compare_routerid>bestpath\scompare-routerid)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath compare-routerid",
            "compval": "bgp.bestpath.compare_routerid",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "compare_routerid": "{{ True if compare_routerid is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_cost_community_ignore",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<cost_community_ignore>bestpath\scost-community\signore)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath cost-community ignore",
            "compval": "bgp.bestpath.cost_community.ignore",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "cost_community": {
                                    "ignore": "{{ True if cost_community_ignore is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_origin_as_use",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<origin_as_use>bestpath\sorigin-as\suse\svalidity)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath origin-as use validity",
            "compval": "bgp.bestpath.origin_as.use.validity",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "origin_as": {
                                    "use": {"validity": "{{ True if origin_as_use is defined }}"},
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_origin_as_allow",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<origin_as_allow>bestpath\sorigin-as\sallow\sinvalid)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath origin-as allow invalid",
            "compval": "bgp.bestpath.origin_as.allow.invalid",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "origin_as":
                                    {
                                        "allow": {"invalid": "{{ True if origin_as_allow is defined }}"},
                                    },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_confederation_identifier",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<confederation_identifier>confederation\sidentifier\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp confederation identifier {{ bgp.confederation.identifier}}",
            "compval": "bgp.confederation.identifier",
            "result": {
                "bgp": {
                    "confederation": {
                        "identifier": "{{confederation_identifier.split(" ")[2]}}",
                    },

                },
            },
        },
        {
            "name": "bgp_confederation_peers",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<confederation_peers>confederation\speers\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_confederation_peers,
            "compval": "bgp.confederation.peers",
            "result": {
                "bgp": {
                    "confederation": {
                        "peers": {
                            "peer" + "{{confederation_peers.split(" ")[2]}}": "{{confederation_peers.split(" ")[2]}}",
                        },
                    },

                },
            },
        },
        {
            "name": "bgp_graceful_restart_set",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<graceful_restart_set>graceful-restart)
                $""", re.VERBOSE,
            ),
            "setval": "bgp graceful-restart",
            "compval": "bgp.graceful_restart.set",
            "result": {
                "bgp": {
                    "graceful_restart": {
                        "set": "{{ True if graceful_restart_set is defined }}",
                    },

                },
            },
        },
        {
            "name": "bgp_graceful_restart_graceful_reset",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<graceful_restart_graceful_reset>graceful-restart\sgraceful-reset)
                $""", re.VERBOSE,
            ),
            "setval": "bgp graceful-restart graceful-reset",
            "compval": "bgp.graceful_restart.graceful_reset",
            "result": {
                "bgp": {
                    "graceful_restart": {
                        "graceful_reset": "{{ True if graceful_restart_graceful_reset is defined}}",
                    },

                },
            },
        },
        {
            "name": "bgp_graceful_restart_restart_time",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<graceful_restart_restart_time>graceful-restart\srestart-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp graceful-restart restart-time {{ bgp.graceful_restart.restart_time}}",
            "compval": "bgp.graceful_restart.restart_time",
            "result": {
                "bgp": {
                    "graceful_restart": {
                        "restart_time": "{{ graceful_restart_restart_time.split(" ")[2] }}",
                    },

                },
            },
        },
        {
            "name": "bgp_graceful_restart_purge_time",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<graceful_restart_purge_time>graceful-restart\spurge-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp graceful-restart purge-time {{ bgp.graceful_restart.purge_time}}",
            "compval": "bgp.graceful_restart.purge_time",
            "result": {
                "bgp": {
                    "graceful_restart": {
                        "purge_time": "{{ graceful_restart_purge_time.split(" ")[2] }}",
                    },

                },
            },
        },
        {
            "name": "bgp_graceful_restart_stalepath_time",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<graceful_restart_stalepath_time>graceful-restart\sstalepath-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp graceful-restart stalepath-time {{ bgp.graceful_restart.stalepath_time}}",
            "compval": "bgp.graceful_restart.stalepath_time",
            "result": {
                "bgp": {
                    "graceful_restart": {
                        "stalepath_time": "{{ graceful_restart_stalepath_time.split(" ")[2] }}",
                    },

                },
            },
        },
        {
            "name": "bgp_log_message",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<log_message>log\smessage\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "bgp log message disable",
            "compval": "bgp.log_message.message.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "log": {
                                "log_message": {"disable": "{{ True if log_message is defined }}"},
                            },
                        },
                    },

                },
            },
        },
        {
            "name": "bgp_log_neighbor_changes_detail",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<log_neighbor_changes_detail>log\sneighbor\schanges\sdetail)
                $""", re.VERBOSE,
            ),
            "setval": "bgp log neighbor changes detail",
            "compval": "bgp.log.neighbor.changes.detail",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "log": {
                                "neighbor": {
                                    "changes": {
                                        "detail": "{{True if log_neighbor_changes_detail is defined }}",
                                    },
                                },
                            },
                        },
                    },

                },
            },
        },
        {
            "name": "bgp_log_neighbor_changes_disable",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<log_neighbor_changes_disable>log\sneighbor\schanges\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "bgp log neighbor changes disable",
            "compval": "bgp.log.neighbor.changes.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "log": {
                                "neighbor": {
                                    "changes": {
                                        "disable":
                                            "{{ True if log_neighbor_changes_disable is defined }}",
                                    },
                                },
                            },
                        },
                    },

                },
            },
        },
        {
            "name": "bgp_multipath_as_path_ignore_onwards",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<multipath>multipath\sas-path\signore\sonwards)
                $""", re.VERBOSE,
            ),
            "setval": "bgp multipath as-path ignore onwards",
            "compval": "bgp.multipath.as_path.ignore.onwards",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bgp": {
                            "multipath": {
                                "as_path": {"ignore": {"onwards": "{{ not not multipath}}"}},
                            },
                        },
                    },

                },
            },
        },
        {
            "name": "bgp_origin_as_validation_disable",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<origin_as_validation_disable>origin-as\svalidation\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "bgp origin-as validation disable",
            "compval": "bgp.origin_as.validation.disable",
            "result": {
                "bgp": {
                    "origin_as": {
                        "validation": {"disable": "{{ not not origin_as_validation_disable}}"},
                    },

                },
            },
        },
        {
            "name": "bgp_origin_as_validation_signal_ibgp",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<origin_as_validation_signal_ibgp>origin-as\svalidation\ssignal\sibgp)
                $""", re.VERBOSE,
            ),
            "setval": "bgp origin-as validation signal ibgp",
            "compval": "bgp.origin_as.validation.signal.ibgp",
            "result": {
                "bgp": {
                    "origin_as": {
                        "validation": {"signal": {"ibgp": "{{ not not origin_as_validation_signal_ibgp }}"}},
                    },

                },
            },
        },
        {
            "name": "bgp_origin_as_validation_time_off",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<validation_time_off>origin-as\svalidation\stime\soff)
                $""", re.VERBOSE,
            ),
            "setval": "bgp origin-as validation time off",
            "compval": "bgp.origin_as.validation.time.off",
            "result": {
                "bgp": {
                    "origin_as": {
                        "validation": {"time": {"time_off": "{{ not not validation_time_off }}"}},
                    },

                },
            },
        },
        {
            "name": "bgp_origin_as_validation_time",
            "getval": re.compile(
                r"""
                \s+bgp\s(?P<validation_time>origin-as\svalidation\stime\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp origin-as validation time {{ bgp.origin_as.validation.time.time_in_second }}",
            "compval": "bgp.origin_as.validation.time.time_in_second",
            "result": {
                "bgp": {
                    "origin_as": {
                        "validation": {"time": {"time_in_second": "{{ validation_time.split(" ")[3] }}"}},
                    },

                },
            },
        },

        {
            "name": "bgp_default_information_originate",
            "getval": re.compile(
                r"""
                \s+default-information\s(?P<default_information_originate>originate)
                $""", re.VERBOSE,
            ),
            "setval": "default-information originate",
            "compval": "default_information.originate",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "default_information": {
                            "originate": "{{ not not default_information_originate }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_default_metric",
            "getval": re.compile(
                r"""
                \s+default-metric\s(?P<default_metric>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "default-metric {{default_metric}}",
            "compval": "default_metric",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "default_metric": "{{ default_metric }}",
                    },
                },
            },
        },
        {
            "name": "bgp_graceful_maintenance",
            "getval": re.compile(
                r"""
                \s+graceful-maintenance\sactivate\s(?P<graceful_maintenance>\S*)
                $""", re.VERBOSE,
            ),
            "setval": "graceful_maintenance {{graceful_maintenance.activate}}",
            "compval": "graceful_maintenance.activate",
            "result": {
                "graceful_maintenance": {"activate": "{{ graceful_maintenance }}"},
            },
        },
        {
            "name": "ibgp_policy_out_enforce_modifications",
            "getval": re.compile(
                r"""
                \s+ibgp\spolicy\sout\s(?P<ibgp_policy_out>enforce-modifications)
                $""", re.VERBOSE,
            ),
            "setval": "ibgp policy out enforce-modifications",
            "compval": "ibgp.policy.out.enforce_modifications",
            "result": {
                "ibgp": {"policy": {"out": {"enforce_modifications": "{{ not not ibgp_policy_out }}"}}},
            },
        },
        {
            "name": "mpls_activate_interface",
            "getval": re.compile(
                r"""
                \s+mpls\sactivate\sinterface(?P<mpls_interface>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "mpls activate interface {{mpls.activate.interface}}",
            "compval": "mpls.activate.interface",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "mpls": {"activate": {"interface": "{{ mpls_interface }}"}},
                    },
                },
            },
        },
        {
            "name": "mvpn",
            "getval": re.compile(
                r"""
                \s(?P<mvpn>mvpn)
                $""", re.VERBOSE,
            ),
            "setval": "mvpn",
            "compval": "mvpn",
            "result": {
                "mvpn": "{{ not not mvpn }}",
            },
        },
        {
            "name": "nsr_set",
            "getval": re.compile(
                r"""
                \s(?P<nsr>nsr\s*)
                $""", re.VERBOSE,
            ),
            "setval": "nsr",
            "compval": "nsr.set",
            "result": {
                "nsr": {"set": "{{ not not nsr }}"},
            },
        },
        {
            "name": "nsr_disable",
            "getval": re.compile(
                r"""
                \snsr\s(?P<nsr_disable>disable\s*)
                $""", re.VERBOSE,
            ),
            "setval": "nsr disable",
            "compval": "nsr.disable",
            "result": {
                "nsr": {"disable": "{{ not not nsr_disable }}"},
            },
        },
        {
            "name": "socket_receive_buffer_size",
            "getval": re.compile(
                r"""
                \s+socket\s(?P<socket_rcv_buffer_size>receive-buffer-size\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "socket receive-buffer-size {{ socket.receive_buffer_size}}",
            "compval": "socket.receive_buffer_size",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "socket": {"receive_buffer_size": "{{ socket_rcv_buffer_size.split(" ")[1] }}"},
                    },
                },
            },
        },
        {
            "name": "socket_send_buffer_size",
            "getval": re.compile(
                r"""
                \s+socket\s(?P<socket_send_buffer_size>send-buffer-size\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "socket send-buffer-size {{ socket.send_buffer_size}}",
            "compval": "socket.send_buffer_size",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "socket": {"send_buffer_size": "{{ socket_send_buffer_size.split(" ")[1] }}"},
                    },
                },
            },
        },
        {
            "name": "update_in_error_handling_basic_ebgp_disable",
            "getval": re.compile(
                r"""
                \s+update\sin\serror-handling\sbasic\sebgp\s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "update in error-handling basic ebgp disable",
            "compval": "update.in.error_handling.basic.ebgp.disable",
            "result": {
                "update": {"in": {"error_handling": {"basic": {"ebgp": {"disable": "{{ not not disable }}"}}}}},
            },
        },
        {
            "name": "update_in_error_handling_basic_ibgp_disable",
            "getval": re.compile(
                r"""
                \s+update\sin\serror-handling\sbasic\sibgp\s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "update in error-handling basic ibgp disable",
            "compval": "update.in.error_handling.basic.ibgp.disable",
            "result": {
                "update": {"in": {"error_handling": {"basic": {"ibgp": {"disable": "{{ not not disable }}"}}}}},
            },
        },
        {
            "name": "update_in_error_handling_extended_ebgp",
            "getval": re.compile(
                r"""
                \s+update\sin\serror-handling\sextended\s(?P<extended_ebgp>ebgp)
                $""", re.VERBOSE,
            ),
            "setval": "update in error-handling extended ebgp",
            "compval": "update.in.error_handling.extended.ebgp",
            "result": {
                "update": {"in": {"error_handling": {"extended": {"ebgp": "{{ not not extended_ebgp}}"}}}},
            },
        },
        {
            "name": "update_in_error_handling_extended_ibgp",
            "getval": re.compile(
                r"""
                \s+update\sin\serror-handling\sextended\s(?P<extended_ibgp>ibgp)
                $""", re.VERBOSE,
            ),
            "setval": "update in error-handling extended ibgp",
            "compval": "update.in.error_handling.extended.ibgp",
            "result": {
                "update": {"in": {"error_handling": {"extended": {"ibgp": "{{ not not extended_ibgp}}"}}}},
            },
        },
        {
            "name": "update_out_logging",
            "getval": re.compile(
                r"""
                \s+update\sout\s(?P<update_out_logging>logging)
                $""", re.VERBOSE,
            ),
            "setval": "update out logging",
            "compval": "update.out.logging",
            "result": {
                "update": {"out": {"logging": "{{ not not update_out_logging}}"}},
            },
        },
        {
            "name": "update_limit",
            "getval": re.compile(
                r"""
                \s+update\slimit\s(?P<update_limit>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "update limit {{ update.limit }}",
            "compval": "update.limit",
            "result": {
                "update": {"limit": "{{ update_limit}}"},
            },
        },
        {
            "name": "rpki_route_value",
            "getval": re.compile(
                r"""
                \srpki
                \sroute
                \s(?P<value>\S+)
                \smax
                \s(?P<max>\d+)
                \sorigin
                \s(?P<origin>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "rpki route {{ rpki.route.value }} max {{rpki.route.max }} "
                      "origin {{rpki.route.origin }}",
            "compval": "rpki.route",
            "result": {
                "rpki": {
                    "route": {
                        "value": "{{value}}",
                        "origin": "{{origin}}",
                        "max": "{{max}}",
                    },
                },
            },
        },
        {
            "name": "rpki_server_name",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<value>server\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "rpki server {{ name }}",
            "compval": "rpki.server.name",
            "result": {
                "rpki":
                    {
                        "servers": {"{{value.split(" ")[1]}}": {"name": "{{ value.split(" ")[1] }}"}},
                    },
            },
        },
        {
            "name": "rpki_server_purge_time",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<rpki_server>server\s\S+)
                \s(?P<purge_time>purge-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "purge-time {{ purge_time }}",
            "compval": "purge_time",
            "result": {
                "rpki":
                    {
                        "servers": {"{{rpki_server.split(" ")[1]}}": {"purge_time": "{{ purge_time.split(" ")[1] }}"}},
                    },
            },
        },
        {
            "name": "rpki_server_refresh_time",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<rpki_server>server\s\S+)
                \s(?P<refresh_time>refresh-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "refresh-time {{ refresh_time.value }}",
            "compval": "refresh_time.value",
            "result": {
                "rpki": {
                    "servers": {
                        "{{rpki_server.split(" ")[1]}}": {
                            "refresh_time": {
                                "value": "{{ refresh_time.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "rpki_server_refresh_time_off",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<rpki_server>server\s\S+)
                \srefresh-time
                \s(?P<refresh_time>off)
                $""", re.VERBOSE,
            ),
            "setval": "refresh-time off",
            "compval": "refresh_time.time_off",
            "result": {
                "rpki": {
                    "servers": {
                        "{{rpki_server.split(" ")[1] }}": {
                            "refresh_time": {
                                "time_off": "{{ True if refresh_time is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "rpki_server_response_time_off",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<rpki_server>server\s\S+)
                \sresponse-time
                \s(?P<response_time>off)
                $""", re.VERBOSE,
            ),
            "setval": "response-time off",
            "compval": "response_time.time_off",
            "result": {
                "rpki": {
                    "servers": {
                        "{{rpki_server.split(" ")[1]}}": {
                            "response_time": {
                                "time_off": "{{ True if response_time is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "rpki_server_response_time",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<rpki_server>\sserver\S+)
                \s(?P<response_time>response-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "response-time {{ response_time.value }}",
            "compval": "response_time.value",
            "result": {
                "rpki": {
                    "servers": {
                        "{{rpki_server.split(" ")[1]}}": {
                            "response_time": {
                                "value": "{{ response_time.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "rpki_server_shutdown",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<rpki_server>server\s\S+)
                \s(?P<shutdown>shutdown)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown",
            "compval": "shutdown",
            "result": {
                "rpki": {
                    "servers": {"{{rpki_server.split(" ")[1]}}": {"shutdown": "{{ True if shutdown  is defined}}"}},
                },
            },
        },
        {
            "name": "rpki_server_transport_ssh",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<rpki_server>server\s\S+)
                \stransport
                \sssh
                \s(?P<ssh_port>port\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "transport ssh port {{ transport.ssh.port }}",
            "compval": "transport.ssh.port",
            "result": {
                "rpki": {
                    "servers": {
                        "{{rpki_server.split(" ")[1]}}": {
                            "transport": {
                                "ssh": {
                                    "port": "{{ ssh_port.split(" ")[1] }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "rpki_server_transport_tcp",
            "getval": re.compile(
                r"""
                \srpki
                \s(?P<rpki_server>server\s\S+)
                \stransport
                \stcp
                \s(?P<tcp_port>port\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "transport tcp port {{ transport.tcp.port }}",
            "compval": "transport.tcp.port",
            "result": {
                "rpki": {
                    "servers": {
                        "{{rpki_server.split(" ")[1]}}": {
                            "transport": {
                                "tcp": {
                                    "port": "{{ tcp_port.split(" ")[1] }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_address",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<value>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "neighbor {{ neighbor_address }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{value}}":
                                {
                                    "neighbor_address": "{{value}}",
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "advertisement_interval",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<advertise_in>advertisement-interval\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "advertisement-interval {{ advertisement_interval }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "advertisement_interval": "{{ advertise_in.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_fast_detect_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sbfd
                \sfast-detect
                \s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "bfd fast-detect disable",
            "compval": "bfd.fast_detect.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "bfd": {
                                    "fast_detect": {"disable": "{{ True if disable is defined }}"},
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_fast_detect_set",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sbfd
                \s(?P<fast_detect>fast-detect)
                $""", re.VERBOSE,
            ),
            "setval": "bfd fast-detect",
            "compval": "bfd.fast_detect.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "bfd": {
                                    "fast_detect": {"set": "{{ True if fast_detect is defined }}"},
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_fast_detect_strict_mode",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sbfd
                \sfast-detect
                \s(?P<strict_mode>strict-mode)
                $""", re.VERBOSE,
            ),
            "setval": "bfd fast-detect strict-mode",
            "compval": "bfd.fast_detect.strict_mode",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "bfd": {
                                    "fast_detect": {"strict_mode": "{{ True if strict_mode is defined }}"},
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_nbr_multiplier",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \sbfd
                \s(?P<multiplier>multiplier\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "bfd multiplier {{ bfd.multiplier}}",
            "compval": "bfd.multiplier",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}":
                                {
                                    "bfd":
                                    {
                                        "multiplier": "{{multiplier.split(" ")[1]}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_nbr_minimum_interval",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \sbfd
                \s(?P<min_interval>minimum-interval\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "bfd minimum-interval {{ bfd.minimum_interval}}",
            "compval": "bfd.minimum_interval",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}":
                                {
                                    "bfd":
                                    {
                                        "minimum_interval": "{{min_interval.split(" ")[1]}}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "bmp_activate",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sbmp-activate
                \s(?P<bmp_activate>server\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bmp-activate server {{bmp_activate.server}}",
            "compval": "bmp_activate.serevr",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "bmp_activate": {"server": "{{ bmp_activate.split(" ")[1] }}"},
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_cluster_id",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<cluster_id>cluster-id\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "cluster-id {{ cluster_id }}",
            "compval": "cluster_id",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {"cluster_id": "{{ cluster_id.split(" ")[1] }}"},
                        },
                    },
                },

            },
        },
        {
            "name": "neighbor_description",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sdescription\s(?P<description>.+)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "compval": "description",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {"description": "{{ description }}"},
                        },
                    },
                },
            },
        },
        {
            "name": "dmz_link_bandwidth",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<dmz_link_bandwidth>dmz-link-bandwidth)
                $""", re.VERBOSE,
            ),
            "setval": "dmz-link-bandwidth",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}":
                                {
                                    "dmz_link_bandwidth":
                                    {
                                        "set": "{{ True if dmz_link_bandwidth is defined }}",
                                    },
                                },
                        },
                    },
                },
            },
        },
        {
            "name": "dmz_link_bandwidth_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sdmz-link-bandwidth
                \s(?P<dmz_link_bandwidth>inheritance_disable)
                $""", re.VERBOSE,
            ),
            "setval": "dmz-link-bandwidth inheritance-disable",
            "compval": "dmz_link_bandwidth.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "dmz_link_bandwidth":
                                {
                                    "inheritance_disable": "{{ True if dmz_link_bandwidth is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_multihop_value",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ebgp_multihop>ebgp-multihop\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-multihop {{ ebgp_multihop.value}}",
            "compval": "ebgp_multihop.value",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ebgp_multihop": {
                                    "value": "{{ ebgp_multihop.split(" ")[1] }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_multihop_mpls",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ebgp_multihop>ebgp-multihop\s\S*\smpls)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-multihop mpls",
            "compval": "ebgp_multihop.mpls",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ebgp_multihop": {"mpls": "{{ True if ebgp_multihop is defined }}"},
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_recv_extcommunity_dmz",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ebgp_recv_extcommunity_dmz>ebgp-recv-extcommunity-dmz\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-recv-extcommunity-dmz inheritance-disable ",
            "compval": "ebgp_recv_extcommunity_dmz.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ebgp_recv_extcommunity_dmz": {
                                    "inheritance_disable": "{{ True if ebgp_recv_extcommunity_dmz is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_recv_extcommunity_dmz_set",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ebgp_recv_extcommunity_dmz>ebgp-recv-extcommunity-dmz)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-recv-extcommunity-dmz inheritance-disable",
            "compval": "ebgp_recv_extcommunity_dm.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ebgp_recv_extcommunity_dmz": {
                                    "set": "{{ True if ebgp_recv_extcommunity_dmz is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_send_extcommunity_dmz",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ebgp_send_extcommunity_dmz>ebgp-send-extcommunity-dmz\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-send-extcommunity-dmz inheritance-disable ",
            "compval": "ebgp_send_extcommunity_dmz.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ebgp_send_extcommunity_dmz": {
                                    "inheritance_disable": "{{ True if ebgp_send_extcommunity_dmz is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_send_extcommunity_dmz_set",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ebgp_send_extcommunity_dmz>ebgp-send-extcommunity-dmz)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-send-extcommunity-dmz",
            "compval": "ebgp_send_extcommunity_dmz.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ebgp_send_extcommunity_dmz": {
                                    "set": "{{ True if ebgp_send_extcommunity_dmz is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_send_extcommunity_dmz_cumulatie",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ebgp_send_extcommunity_dmz>ebgp-send-extcommunity-dmz\scumulatie)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-send-extcommunity-dmz cumulatie ",
            "compval": "ebgp_send_extcommunity_dmz.cumulatie",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ebgp_send_extcommunity_dmz": {
                                    "cumulatie": "{{ True if ebgp_send_extcommunity_dmz is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "egress_engineering",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<egress_engineering>egress-engineering\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "egress-engineering inheritance-disable ",
            "compval": "egress_engineering.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "egress_engineering": {
                                    "inheritance_disable": "{{ True if egress_engineering is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "egress_engineering_set",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<egress_engineering>egress-engineering)
                $""", re.VERBOSE,
            ),
            "setval": "egress-engineering",
            "compval": "egress_engineering.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "egress_engineering": {
                                    "set": "{{ True if egress_engineering is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_enforce_first_as_disable",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<enforce_first_as_disable>enforce-first-as\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "enforce-first-as disable",
            "compval": "enforce_first_as.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "enforce_first_as": {
                                    "disable": "{{ True if enforce_first_as_disable is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_restart_restart_time",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<graceful_restart_restart_time>graceful-restart\srestart-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-restart restart-time {{ graceful_restart.restart_time}}",
            "compval": "graceful_restart.restart_time",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_restart": {
                                    "restart_time": "{{ graceful_restart_restart_time.split(" ")[2] }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_restart_stalepath_time",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<graceful_restart_stalepath_time>graceful-restart\sstalepath-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-restart stalepath-time {{ graceful_restart.stalepath_time}}",
            "compval": "graceful_restart.stalepath_time",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_restart": {
                                    "stalepath_time": "{{ graceful_restart_stalepath_time.split(" ")[2] }}",
                                },
                            },
                        },
                    },

                },
            },
        },
        {
            "name": "ignore_connected_check_set",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ignore_connected_check>ignore-connected-check)
                $""", re.VERBOSE,
            ),
            "setval": "ignore-connected-check",
            "compval": "ignore_connected_check.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ignore_connected_check": {
                                    "set": "{{ True if ignore_connected_check is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ignore_connected_check",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ignore_connected_check>ignore-connected-check\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "ignore-connected-check inheritance-disable ",
            "compval": "ignore_connected_check.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ignore_connected_check": {
                                    "inheritance_disable": "{{ True if ignore_connected_check is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "keychain",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<keychain>keychain\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "keychain inheritance-disable ",
            "compval": "keychain.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "keychain": {
                                    "inheritance_disable": "{{ True if keychain is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "keychain_name",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<keychain>keychain\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "keychain {{ name }}",
            "compval": "keychain.name",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "keychain": {
                                    "name": "{{ keychain.split(" ")[1] }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "remote_as",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<remote_as>remote-as\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "remote-as {{ remote_as }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "remote_as": "{{ remote_as.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "local_as_inheritance_disable",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<local_as>local-as\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "local-as inheritance-disable",
            "compval": "local_as.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "local_as": {
                                    "inheritance_disable": "{{ True if local_as is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "local_as",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<local_as>local-as\s\S+)
                (\s(?P<no_prepend>no-prepend))?
                (\s(?P<replace_as>replace-as))?
                (\s(?P<dual_as>dual-as))?
                $""", re.VERBOSE,
            ),
            "setval": _templ_local_as,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "local_as": {
                                    "value": "{{ local_as.split(" ")[1] }}",
                                    "no_prepend":
                                        {
                                            "set": "{{ True if no_prepend is defined and replace_as is undefined and dual_as is undefined else None}}",
                                            "replace_as": {
                                                "set": "{{ True if replace_as is defined and dual_as is undefined}}",
                                                "dual_as": "{{ not not dual_as}}",
                                            },
                                        },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "local_address",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \slocal
                \s(?P<local>address\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "local address inheritance-disable",
            "compval": "local.address.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "local": {
                                    "address": {
                                        "inheritance_disable": "{{ True if local is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "local",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \slocal
                \s(?P<local>address\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "local address {{ local.address.ipv4_address }}",
            "compval": "local.address.ipv4_address",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "local": {
                                    "address": {
                                        "ipv4_address": "{{ local.split(" ")[1] }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "origin_as",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sorigin-as
                \s(?P<origin_as>validation\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "origin-as validation disable",
            "compval": "origin-as.validation.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "origin_as": {
                                    "validation": {
                                        "disable": "{{ True if origin_as is defined}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "password_inheritance_disable",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<password>password\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "password inheritance-disable",
            "compval": "password.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "password": {
                                    "inheritance_disable": "{{ True if password is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "password_encrypted",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \spassword\sencrypted
                \s(?P<password>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "password encrypted {{password.encrypted}}",
            "compval": "password.encrypted",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "password": {
                                    "encrypted": "{{ password }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "receive_buffer_size",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<receive_buffer_size>receive-buffer-size\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "receive-buffer-size {{ receive_buffer_size }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "receive_buffer_size": "{{ receive_buffer_size.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "send_buffer_size",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<send_buffer_size>send-buffer-size\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "send-buffer-size {{ send_buffer_size }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "send_buffer_size": "{{ send_buffer_size.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "session_open_mode",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<session_open_mode>session-open-mode\s(active-only|both|passive-only))
                $""", re.VERBOSE,
            ),
            "setval": "session-open-mode {{ session_open_mode }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "session_open_mode": "{{ session_open_mode.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_shutdown",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<shutdown>shutdown)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown",
            "compval": "shutdown",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "shutdown": {
                                    "set": "{{ True if shutdown is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_shutdown_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<shutdown>shutdown\sinheritance_disable)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown inheritance-disable",
            "compval": "shutdown.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "shutdown": {"inheritance_disable": "{{ True if shutdown is defined }}"},
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "dscp",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<dscp>dscp\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "dscp {{ dscp }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "dscp": "{{ dscp.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_tcp_mss_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<tcp_mss_disable>tcp\smss\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "tcp mss inheritance-disable",
            "compval": "tcp.mss.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "tcp": {
                                    "mss": {
                                        "inheritance_disable": "{{ True if tcp_mss_disable is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_tcp_mss",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<tcp_mss>tcp\smss\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "tcp mss {{ tcp.mss.value }}",
            "compval": "tcp.mss.value",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "tcp": {
                                    "mss": {
                                        "value": "{{ tcp_mss.split(" ")[2] }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_timers_keepalive",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<timers_keepalive_time>timers\s\d+)
                \s(?P<timers_holdtime>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "timers {{ timers.keepalive_time}} {{ timers.holdtime }}",
            "compval": "timers",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "timers": {
                                    "keepalive_time": "{{ timers_keepalive_time.split(" ")[1] }}",
                                    "holdtime": "{{ timers_holdtime.split(" ")[0] }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "use.neighbor_group",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \suse\sneighbor-group\s(?P<neighbor_group>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "use neighbor-group {{ use.neighbor_group }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "use": {
                                    "neighbor_group": "{{ neighbor_group }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "use.session_group",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \suse\ssession-group\s(?P<session_group>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "use session-group {{ use.session_group }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "use": {
                                    "session_group": "{{ session_group }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "update_source",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \supdate-source
                \s(?P<update_source>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "update-source {{ update_source}}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "update_source": "{{ update_source}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_ttl_security_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ttl_security>ttl-security\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "ttl-security inheritance-disable",
            "compval": "ttl_security.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ttl_security": {
                                    "inheritance_disable": "{{ True if ttl_security is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_ttl_security",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<ttl_security>ttl-security)
                $""", re.VERBOSE,
            ),
            "setval": "ttl-security",
            "compval": "ttl_security.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "ttl_security": {
                                    "set": "{{ True if ttl_security is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_set",
            "getval": re.compile(
                r"""
               \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<graceful_maintenance>graceful-maintenance)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance",
            "compval": "graceful_maintenance.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_maintenance": {
                                    "set": "{{ True if graceful_maintenance is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_activate",
            "getval": re.compile(
                r"""
               \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<graceful_maintenance>graceful-maintenance\sactivate)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance activate",
            "compval": "graceful_maintenance.activate.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_maintenance": {
                                    "activate": {"set": "{{ True if graceful_maintenance is defined }}"},
                                },
                            },
                        },
                    },
                },
            },
        },

        {
            "name": "neighbor_graceful_maintenance_activate_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<graceful_maintenance>activate\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance activate inheritance-disable",
            "compval": "graceful_maintenance.activate.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_maintenance": {
                                    "activate": {
                                        "inheritance_disable": "{{ True if graceful_maintenance is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_as_prepends",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<as_prepends>as-prepends\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance as-prepends inheritance-disable",
            "compval": "graceful_maintenance.as_prepends.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_maintenance": {
                                    "as_prepends": {
                                        "inheritance_disable": "{{ True if as_prepends is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_local_preference_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<local_preference>local-preference\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance local-preference inheritance-disable",
            "compval": "graceful_maintenance.local_preference.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_maintenance": {
                                    "local_preference": {
                                        "inheritance_disable": "{{ True if local_preference is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_local_preference",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<local_preference>local-preference\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance local-preference {{ graceful_maintenance.local_preference.value}}",
            "compval": "graceful_maintenance.local_preference.value",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_maintenance": {
                                    "local_preference": {
                                        "value": "{{ local_preference.split(" ")[1]}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_as_prepends_value",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<as_prepends>as-prepends\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance as-prepends {{ graceful_maintenance.as_prepends.value }}",
            "compval": "graceful_maintenance.as_prepends.value",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "graceful_maintenance": {
                                    "as_prepends": {
                                        "value": "{{ as_prepends.split(" ")[1]}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_additional_paths_send",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \scapability
                \sadditional-paths
                \s(?P<additional_paths_send>send)
                $""", re.VERBOSE,
            ),
            "setval": "capability additional-paths send",
            "compval": "capability.additional_paths.send.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "capability": {
                                    "additional_paths": {
                                        "send": {
                                            "set": "{{ True if additional_paths_send is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_additional_paths_send_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \scapability
                \sadditional-paths
                \s(?P<additional_paths_send>send\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "capability additional-paths send disable",
            "compval": "capability.additional_paths.send.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "capability": {
                                    "additional_paths": {
                                        "send": {
                                            "disable": "{{ True if additional_paths_send is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_additional_paths_rcv",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \scapability
                \sadditional-paths
                \s(?P<additional_paths_receive>receive)
                $""", re.VERBOSE,
            ),
            "setval": "capability additional-paths receive",
            "compval": "capability.additional_paths.receive.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "capability": {
                                    "additional_paths": {
                                        "receive": {
                                            "set": "{{ True if additional_paths_receive is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_additional_paths_rcv_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \scapability
                \sadditional-paths
                \s(?P<additional_paths_receive_disable>receive\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "capability additional-paths receive disable",
            "compval": "capability.additional_paths.receive.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "capability": {
                                    "additional_paths": {
                                        "receive": {
                                            "disable": "{{ True if additional_paths_receive_disable is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_suppress_four_byte_AS",
            "getval": re.compile(
                r"""
               \s+(?P<nbr_address>neighbor\s\S+)
                \scapability
                \ssuppress
                \s(?P<suppress_4_byte_as>4-byte-as)
                $""", re.VERBOSE,
            ),
            "setval": "capability suppress 4-byte-as",
            "compval": "capability.suppress.four_byte_AS.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "capability": {
                                    "suppress": {
                                        "four_byte_AS": {
                                            "set": "{{ True if suppress_4_byte_as is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_suppress_all",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \scapability
                \ssuppress
                \s(?P<all>all)
                $""", re.VERBOSE,
            ),
            "setval": "capability suppress all",
            "compval": "capability.suppress.all.set",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "capability": {
                                    "suppress": {
                                        "all": {
                                            "set": "{{ True if all is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_suppress_all_inheritance_disable",
            "getval": re.compile(
                r"""
               \s+(?P<nbr_address>neighbor\s\S+)
                \scapability
                \ssuppress
                \s(?P<all>all\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "capability suppress all inheritance-disable",
            "compval": "capability.suppress.all.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "capability": {
                                    "suppress": {
                                        "all": {
                                            "inheritance_disable": "{{ True if all is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },

        {
            "name": "neighbor_log_message_in_value",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \slog
                \smessage
                \s(?P<value>in\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "log message in {{ log.message.in.value}}",
            "compval": "log.log_message.in.value",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "log": {
                                    "log_message": {
                                        "in": {
                                            "value": "{{ value.split(" ")[1] }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_in_disable",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \slog
                \smessage
                \s(?P<disable>in\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "log message in disable",
            "compval": "log.log_message.in.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "log": {
                                    "log_message": {
                                        "in": {
                                            "disable": "{{ True if disable is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_in_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \slog
                \smessage
                \s(?P<disable>in\sinheritance-diable)
                $""", re.VERBOSE,
            ),
            "setval": "log message in inheritance-diable",
            "compval": "log.log_message.in.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "log": {
                                    "log_message": {
                                        "in": {
                                            "inheritance_disable": "{{ True if disable is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_out_value",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \slog
                \smessage
                \s(?P<value>out\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "log message out {{ log.message.out.value}}",
            "compval": "log.log_message.out.value",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "log": {
                                    "log_message": {
                                        "out": {
                                            "value": "{{ value.split(" ")[1] }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_out_disable",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \slog
                \smessage
                \s(?P<disable>out\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "log message out disable",
            "compval": "log.log_message.out.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "log": {
                                    "log_message": {
                                        "out": {
                                            "disable": "{{ True if disable is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_out_inheritance_disable",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \slog
                \smessage
                \s(?P<disable>out\sinheritance-diable)
                $""", re.VERBOSE,
            ),
            "setval": "log message out inheritance-diable",
            "compval": "log.log_message.out.inheritance_disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "log": {
                                    "log_message": {
                                        "out": {
                                            "inheritance_disable": "{{ True if disable is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_update_in_filtering_attribute_filter_group",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<attribute_filter_group>attribute-filter\sgroup\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "update in filtering attribute-filter group {{ update.in.filtering.attribute_filter.group }}",
            "compval": "update.in.filtering.attribute_filter.group",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "update": {
                                    "in": {
                                        "filtering": {
                                            "attribute_filter": {
                                                "group": "{{ attribute_filter_group.split(" ")[2] }}",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_update_in_filtering_logging_disable",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<logging_disable>logging\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "update in filtering logging disable",
            "compval": "update.in.filtering.logging.disable",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "update": {
                                    "in": {
                                        "filtering": {
                                            "logging": {
                                                "disable": "{{True if logging_disable is defined }}",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_update_in_filtering_message_buffers",
            "getval": re.compile(
                r"""
                 \s+(?P<nbr_address>neighbor\s\S+)
                \s(?P<message_buffers>message\sbuffers\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "update in filtering message buffers {{ update.in.filtering.message.buffers}}",
            "compval": "update.in.filtering.update_message.buffers",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "update": {
                                    "in": {
                                        "filtering": {
                                            "update_message": {
                                                "buffers": "{{ message_buffers.split(" ")[2] }}",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "rd_auto",
            "getval": re.compile(
                r"""
                \s+rd(?P<rd_auto>\sauto)
                $""", re.VERBOSE,
            ),
            "setval": "rd auto",
            "compval": "rd.auto",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "rd": {
                            "auto": "{{True if rd_auto is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "timers_keepalive",
            "getval": re.compile(
                r"""
                \s+timers\sbgp\s(?P<timers_keepalive_time>\d+)\s(?P<hold_time>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "timers bgp {{ timers.keepalive_time}} {{ timers.holdtime}}",
            "compval": "timers",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "timers": {
                            "keepalive_time": "{{ timers_keepalive_time }}",
                            "holdtime": "{{ hold_time}}",
                        },
                    },
                },
            },
        },

    ]
    # fmt: on
