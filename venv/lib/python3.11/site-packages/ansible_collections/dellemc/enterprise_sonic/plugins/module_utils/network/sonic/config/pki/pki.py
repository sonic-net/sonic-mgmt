#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell EMC
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_pki class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
    remove_empties,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import (
    Facts,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
)

from urllib.parse import quote


TRUST_STORES_PATH = "data/openconfig-pki:pki/trust-stores"
SECURITY_PROFILES_PATH = "data/openconfig-pki:pki/security-profiles"
TRUST_STORE_PATH = "data/openconfig-pki:pki/trust-stores/trust-store"
SECURITY_PROFILE_PATH = (
    "data/openconfig-pki:pki/security-profiles/security-profile"
)

PATCH = "patch"
DELETE = "delete"
PUT = "put"
TEST_KEYS = [
    {"security_profiles": {"profile_name": ""}},
    {"trust_stores": {"name": ""}},
]


class Pki(ConfigBase):
    """
    The sonic_pki class
    """

    gather_subset = [
        "!all",
        "!min",
    ]

    gather_network_resources = [
        "pki",
    ]

    def get_pki_facts(self):
        """Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(
            self.gather_subset, self.gather_network_resources
        )
        pki_facts = facts["ansible_network_resources"].get("pki")
        if not pki_facts:
            return {}
        return pki_facts

    def execute_module(self):
        """Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {"changed": False}
        warnings = list()
        commands = list()

        existing_pki_facts = self.get_pki_facts()
        commands, requests = self.set_config(existing_pki_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(
                        self._module, to_request(self._module, requests)
                    )
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result["changed"] = True
        result["commands"] = commands

        changed_pki_facts = self.get_pki_facts()

        result["before"] = existing_pki_facts
        if result["changed"]:
            result["after"] = changed_pki_facts

        result["warnings"] = warnings

        return result

    def set_config(self, existing_pki_facts):
        """Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params["config"]
        have = existing_pki_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        state = self._module.params["state"]
        if not want:
            want = {}

        diff = get_diff(want, have, list(TEST_KEYS))

        if state == "overridden":
            commands, requests = self._state_overridden(want, have, diff)
        elif state == "deleted":
            commands, requests = self._state_deleted(want, have, diff)
        elif state == "merged":
            commands, requests = self._state_merged(want, have, diff)
        elif state == "replaced":
            commands, requests = self._state_replaced(want, have)
        return commands, requests

    def _state_replaced(self, want, have):
        """Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        spdiff = sp_diff(want, have)
        tsdiff = ts_diff(want, have)
        commands = []
        requests = []
        have_dict = {
            "security_profiles": {
                sp.get("profile_name"): sp
                for sp in (have.get("security_profiles") or [])
            },
            "trust_stores": {
                ts.get("name"): ts for ts in (have.get("trust_stores") or [])
            },
        }
        for ts in tsdiff:
            requests.append(
                {
                    "path": TRUST_STORE_PATH + "=" + ts.get("name"),
                    "method": PUT,
                    "data": mk_ts_config(ts),
                }
            )
            commands.append(
                update_states(
                    have_dict["trust_stores"][ts.get("name")], "replaced"
                )
            )
        for sp in spdiff:
            requests.append(
                {
                    "path": SECURITY_PROFILE_PATH
                    + "="
                    + sp.get("profile_name"),
                    "method": PUT,
                    "data": mk_sp_config(sp),
                }
            )
            commands.append(
                update_states(
                    have_dict["security_profiles"][sp.get("profile_name")],
                    "replaced",
                )
            )

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """

        commands = []
        requests = []
        want_tss = [ts.get("name") for ts in (want.get("trust_stores") or [])]
        want_sps = [
            sp.get("profile_name")
            for sp in (want.get("security_profiles") or [])
        ]
        have_tss = [ts.get("name") for ts in (have.get("trust_stores") or [])]
        have_sps = [
            sp.get("profile_name")
            for sp in (have.get("security_profiles") or [])
        ]

        have_dict = {
            "security_profiles": {
                sp.get("profile_name"): sp
                for sp in (have.get("security_profiles") or [])
            },
            "trust_stores": {
                ts.get("name"): ts for ts in (have.get("trust_stores") or [])
            },
        }
        used_ts = []
        for sp in have_sps:
            if sp not in want_sps:
                requests.append(
                    {
                        "path": SECURITY_PROFILE_PATH + "=" + sp,
                        "method": DELETE,
                    }
                )
                commands.append(
                    update_states(
                        have_dict["security_profiles"][sp], "deleted"
                    )
                )
            else:
                ts_name = have_dict.get("security_profiles", {}).get(sp, {}).get("trust_store")
                if ts_name and ts_name not in used_ts:
                    used_ts.append(ts_name)

        for ts in have_tss:
            if ts not in want_tss and ts not in used_ts:
                requests.append(
                    {"path": TRUST_STORE_PATH + "=" + ts, "method": DELETE}
                )
                commands.append(
                    update_states(have_dict["trust_stores"][ts], "deleted")
                )

        for ts in want.get("trust_stores") or []:
            if ts != have_dict["trust_stores"].get(ts.get("name")):
                requests.append(
                    {
                        "path": TRUST_STORE_PATH + "=" + ts.get("name"),
                        "method": PUT,
                        "data": mk_ts_config(ts),
                    }
                )
                commands.append(update_states(ts, "overridden"))
        for sp in want.get("security_profiles") or []:
            if sp != have_dict["security_profiles"].get(
                sp.get("profile_name")
            ):
                requests.append(
                    {
                        "path": SECURITY_PROFILE_PATH
                        + "="
                        + sp.get("profile_name"),
                        "method": PUT,
                        "data": mk_sp_config(sp),
                    }
                )
                commands.append(update_states(sp, "overridden"))

        return commands, requests

    def _state_merged(self, want, have, diff):
        """The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff or {}
        requests = []

        for ts in commands.get("trust_stores") or []:
            requests.append(
                {
                    "path": TRUST_STORE_PATH,
                    "method": PATCH,
                    "data": mk_ts_config(ts),
                }
            )

        for sp in commands.get("security_profiles") or []:
            requests.append(
                {
                    "path": SECURITY_PROFILE_PATH,
                    "method": PATCH,
                    "data": mk_sp_config(sp),
                }
            )

        if commands and requests:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []
        current_ts = [
            ts.get("name")
            for ts in (have.get("trust_stores") or [])
            if ts.get("name")
        ]
        current_sp = [
            sp.get("profile_name")
            for sp in (have.get("security_profiles") or [])
            if sp.get("profile_name")
        ]
        if not want:
            commands = have
            for sp in current_sp:
                requests.append(
                    {
                        "path": SECURITY_PROFILE_PATH + "=" + sp,
                        "method": DELETE,
                    }
                )
            for ts in current_ts:
                requests.append(
                    {"path": TRUST_STORE_PATH + "=" + ts, "method": DELETE}
                )
        else:
            commands = remove_empties(want)

            for sp in commands.get("security_profiles") or []:
                if sp.get("profile_name") in current_sp:
                    requests.extend(mk_sp_delete(sp, have))
            for ts in commands.get("trust_stores") or []:
                if ts.get("name") in current_ts:
                    requests.extend(mk_ts_delete(ts, have))

        if commands and requests:
            commands = update_states([commands], "deleted")
        else:
            commands = []

        return commands, requests


def sp_diff(want, have):
    hsps = {}
    wsps = {}
    dsps = []
    for hsp in have.get("security_profiles") or []:
        hsps[hsp.get("profile_name")] = hsp
    for wsp in want.get("security_profiles") or []:
        wsps[wsp.get("profile_name")] = wsp

    for spn, sp in wsps.items():
        dsp = dict(hsps.get(spn))
        # Pop each leaf from dsp that is not in sp
        for k, v in dsp.items():
            if not isinstance(dsp.get(k), list) and not isinstance(
                dsp.get(k), dict
            ):
                if k not in sp:
                    dsp.pop(k)
        for k, v in sp.items():
            if not isinstance(dsp.get(k), list) and not isinstance(
                dsp.get(k), dict
            ):
                if dsp.get(k) != v:
                    dsp[k] = v
            else:
                if v is not None:
                    dsp[k] = v
        if dsp != hsps.get(spn):
            dsps.append(dsp)
    return dsps


def ts_diff(want, have):
    htss = {}
    wtss = {}
    dtss = []
    for hts in have.get("trust_stores") or []:
        htss[hts.get("name")] = hts
    for wts in want.get("trust_stores") or []:
        wtss[wts.get("name")] = wts

    for tsn, ts in wtss.items():
        dts = dict(htss.get(tsn))
        for k, v in ts.items():
            if not isinstance(dts.get(k), list) and not isinstance(
                dts.get(k), dict
            ):
                if dts.get(k) != v:
                    dts[k] = v
            else:
                if v is not None:
                    dts[k] = v
        if dts != htss.get(tsn):
            dtss.append(dts)
    return dtss


def mk_sp_config(indata):
    outdata = {
        k.replace("_", "-"): v for k, v in indata.items() if v is not None
    }
    output = {
        "openconfig-pki:security-profile": [
            {"profile-name": outdata.get("profile-name"), "config": outdata}
        ]
    }
    return output


def mk_ts_config(indata):
    outdata = {
        k.replace("_", "-"): v for k, v in indata.items() if v is not None
    }
    output = {
        "openconfig-pki:trust-store": [
            {"name": outdata.get("name"), "config": outdata}
        ]
    }
    return output


def mk_sp_delete(want_sp, have):
    requests = []
    cur_sp = None
    del_sp = {}
    for csp in have.get("security_profiles") or []:
        if csp.get("profile_name") == want_sp.get("profile_name"):
            cur_sp = csp
            break
    if cur_sp:
        for k, v in want_sp.items():
            if v is not None and k != "profile_name":
                if v == cur_sp.get(k) or isinstance(v, list):
                    del_sp[k] = v
    if len(del_sp) == 0 and len(want_sp) <= 1:
        requests = [
            {
                "path": SECURITY_PROFILE_PATH
                + "="
                + want_sp.get("profile_name"),
                "method": DELETE,
            }
        ]
    else:
        for k, v in del_sp.items():
            if isinstance(v, list):
                for li in v:
                    if li in (cur_sp.get(k) or []):
                        requests.append(
                            {
                                "path": SECURITY_PROFILE_PATH
                                + "="
                                + want_sp.get("profile_name")
                                + "/config/"
                                + k.replace("_", "-")
                                + "="
                                + quote(li, safe=""),
                                "method": DELETE,
                            }
                        )
            else:
                requests.append(
                    {
                        "path": SECURITY_PROFILE_PATH
                        + "="
                        + want_sp.get("profile_name")
                        + "/config/"
                        + k.replace("_", "-"),
                        "method": DELETE,
                    }
                )
    return requests


def mk_ts_delete(want_ts, have):
    requests = []
    cur_ts = None
    del_ts = {}
    for cts in have.get("trust_stores") or []:
        if cts.get("name") == want_ts.get("name"):
            cur_ts = cts
            break
    if cur_ts:
        for k, v in want_ts.items():
            if v is not None and k != "name":
                if v == cur_ts.get(k) or isinstance(v, list):
                    del_ts[k] = v
    if len(del_ts) == 0 and len(want_ts) <= 1:
        requests = [
            {
                "path": TRUST_STORE_PATH + "=" + want_ts.get("name"),
                "method": DELETE,
            }
        ]
    else:
        for k, v in del_ts.items():
            if isinstance(v, list):
                for li in v:
                    if li in (cur_ts.get(k) or []):
                        requests.append(
                            {
                                "path": TRUST_STORE_PATH
                                + "="
                                + want_ts.get("name")
                                + "/config/"
                                + k.replace("_", "-")
                                + "="
                                + quote(li, safe=""),
                                "method": DELETE,
                            }
                        )
            else:
                requests.append(
                    {
                        "path": TRUST_STORE_PATH
                        + "="
                        + want_ts.get("name")
                        + "/config/"
                        + k.replace("_", "-"),
                        "method": DELETE,
                    }
                )
    return requests
