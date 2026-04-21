# This file is maintained in the vmware_rest_code_generator project
# https://github.com/ansible-collections/vmware_rest_code_generator
# Copyright (c) 2021 Ansible Project
#
# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import hashlib
import importlib
import json
import re
import urllib.parse

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.parsing.convert_bool import boolean

try:
    from ansible_collections.cloud.common.plugins.module_utils.turbo.exceptions import (
        EmbeddedModuleFailure as ModuleFailureException,
    )
except ImportError:
    ModuleFailureException = Exception


async def open_session(
    vcenter_hostname=None,
    vcenter_username=None,
    vcenter_password=None,
    validate_certs=True,
    log_file=None,
):
    validate_certs = boolean(validate_certs)
    m = hashlib.sha256()
    m.update(vcenter_hostname.encode())
    m.update(vcenter_username.encode())
    m.update(vcenter_password.encode())
    if log_file:
        m.update(log_file.encode())
    m.update(b"yes" if validate_certs else b"no")
    digest = m.hexdigest()
    # TODO: Handle session timeout
    if digest in open_session._pool:
        return open_session._pool[digest]

    try:
        aiohttp = importlib.import_module("aiohttp")
    except ImportError:
        raise ModuleFailureException(missing_required_lib("aiohttp"))

    if not aiohttp:
        raise ModuleFailureException("Failed to import aiohttp")

    if log_file:
        trace_config = aiohttp.TraceConfig()

        async def on_request_end(session, trace_config_ctx, params):
            with open(log_file, "a+", encoding="utf-8") as fd:
                answer = await params.response.text()
                fd.write(
                    f"{params.method}: {params.url}\n"
                    f"headers: {params.headers}\n"
                    f"  status: {params.response.status}\n"
                    f"  answer: {answer}\n\n"
                )

        trace_config.on_request_end.append(on_request_end)
        trace_configs = [trace_config]
    else:
        trace_configs = []

    auth = aiohttp.BasicAuth(vcenter_username, vcenter_password)
    if validate_certs:
        connector = aiohttp.TCPConnector(limit=20)
    else:
        connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(
        connector=connector, connector_owner=False, trace_configs=trace_configs
    ) as session:
        try:
            async with session.post(
                "https://{hostname}/rest/com/vmware/cis/session".format(
                    hostname=vcenter_hostname
                ),
                auth=auth,
            ) as resp:
                if resp.status != 200:
                    raise ModuleFailureException(
                        "Authentication failure. code: {0}, json: {1}".format(
                            resp.status, await resp.text()
                        )
                    )
                json = await resp.json()
        except aiohttp.client_exceptions.ClientConnectorError as e:
            raise ModuleFailureException(f"Authentication failure: {e}")

    session_id = json["value"]
    session = aiohttp.ClientSession(
        connector=connector,
        headers={
            "vmware-api-session-id": session_id,
            "content-type": "application/json",
        },
        connector_owner=False,
        trace_configs=trace_configs,
    )
    open_session._pool[digest] = session
    return session


open_session._pool = {}


def gen_args(params, in_query_parameter):
    elements = []
    for i in in_query_parameter:
        if i.startswith("filter."):  # < 7.0.2
            v = params.get("filter_" + i[7:])
        else:
            v = params.get(i)
        if not v:
            continue
        if isinstance(v, list):
            for j in v:
                elements += [(i, j)]
        elif isinstance(v, bool) and v:
            elements += [(i, str(v).lower())]
        else:
            elements += [(i, str(v))]
    if not elements:
        return ""
    return "?" + urllib.parse.urlencode(elements, quote_via=urllib.parse.quote)


def session_timeout(params):
    try:
        aiohttp = importlib.import_module("aiohttp")
    except ImportError:
        raise ModuleFailureException(missing_required_lib("aiohttp"))

    if not aiohttp:
        raise ModuleFailureException("Failed to import aiohttp")
    out = {}
    if params.get("session_timeout"):
        out["timeout"] = aiohttp.ClientTimeout(total=params.get("session_timeout"))
    return out


async def update_changed_flag(data, status, operation):
    if data is None:
        data = {"value": {}}
    elif isinstance(data, list):  # e.g: appliance_infraprofile_configs_info
        data = {"value": data}
    elif isinstance(data, str):
        data = {"value": data}
    elif isinstance(data, dict) and "value" not in data:  # 7.0.2+
        data = {"value": data}
    elif isinstance(data, bool):
        data = {"value": data}

    if isinstance(data["value"], str) and data["value"][0] in [
        "{",
        "]",
    ]:  # e.g: appliance_infraprofile_configs
        data["value"] == json.loads(data["value"])

    if status == 500:
        data["failed"] = True
        data["changed"] = False
    elif operation in ["create", "clone", "instant_clone"] and status in [200, 201]:
        data["failed"] = False
        data["changed"] = True
    elif operation == "update" and status in [200, 204]:
        data["failed"] = False
        data["changed"] = True
    elif operation in ["upgrade", "create_temporary"] and status == 200:
        data["failed"] = False
        data["changed"] = True
    elif operation == "set" and status in [200, 204]:
        data["failed"] = False
        data["changed"] = True
    elif operation == "delete" and status in [200, 204]:
        data["failed"] = False
        data["changed"] = True
    elif operation in ["create", "move"] and status in [204]:
        data["failed"] = False
        data["changed"] = True
    elif operation == "delete" and status == 404:
        data["failed"] = False
        data["changed"] = False
    elif operation in ["get", "list"] and status in [200]:
        data["failed"] = False
        data["changed"] = False
    elif operation in ["get", "list"] and status in [404]:
        data["failed"] = True
        data["changed"] = False

    elif status >= 400:
        data["failed"] = True
        data["changed"] = False

    if not isinstance(data["value"], dict):
        pass
    elif data.get("type") == "com.vmware.vapi.std.errors.not_found":
        if operation == "delete":
            data["failed"] = False
            data["changed"] = False
        else:
            data["failed"] = True
            data["changed"] = False
    elif data.get("type") == "com.vmware.vapi.std.errors.already_in_desired_state":
        data["failed"] = False
        data["changed"] = False
    elif data.get("type") == "com.vmware.vapi.std.errors.already_exists":
        data["failed"] = False
        data["changed"] = False
    elif (
        data.get("value", {}).get("error_type") in ["NOT_FOUND"]
        and operation == "delete"
    ):
        data["failed"] = False
        data["changed"] = False
    elif data.get("value", {}).get("error_type") in [
        "ALREADY_EXISTS",
        "ALREADY_IN_DESIRED_STATE",
    ]:
        data["failed"] = False
        data["changed"] = False
    elif data.get("type") == "com.vmware.vapi.std.errors.resource_in_use":
        # NOTE: this is a shortcut/hack. We get this issue if a CDROM already exists
        data["failed"] = False
        data["changed"] = False
    elif (
        data.get("type") == "com.vmware.vapi.std.errors.internal_server_error"
        and data["value"]
        and data["value"]["messages"]
        and data["value"]["messages"][0]["args"]
        == [
            "com.vmware.vim.binding.vim.fault.DuplicateName cannot be cast to com.vmware.vim.binding.vim.fault.AlreadyConnected"
        ]
    ):
        # NOTE: another one for vcenter_host
        data["failed"] = False
        data["changed"] = False
    elif data.get("type", "").startswith("com.vmware.vapi.std.errors"):
        data["failed"] = True
    # 7.0.3, vcenter_ovf_libraryitem returns status 200 on failure
    elif data.get("value", {}).get("error", {}).get("errors", []):
        data["failed"] = True

    return data


async def list_devices(session, url):
    pass

    async with session.get(url) as resp:
        _json = await resp.json()
        return _json


async def build_full_device_list(session, url, device_list):
    import asyncio

    device_ids = []

    if isinstance(device_list, list):
        value = device_list
    else:  # 7.0.2 <
        value = device_list["value"]
    for i in value:
        # Content library returns string {"value": "library_id"}
        if isinstance(i, str):
            device_ids.append(i)
            continue
        fields = list(i.values())
        if len(fields) != 1:
            # The list already comes with all the details
            return device_list
        device_ids.append(fields[0])

    tasks = [
        asyncio.ensure_future(get_device_info(session, url, _id)) for _id in device_ids
    ]

    return [await i for i in tasks]


async def get_device_info(session, url, _id):
    # remove the action=foo from the URL
    m = re.search("(.+)(action=[-a-z]+)(.*)", url)
    if m:
        url = f"{m.group(1)}{m.group(3)}"
        url = url.rstrip("?")

    # workaround for content_library_item_info
    if "item?library_id=" in url:
        item_url = url.split("?")[0] + "/" + _id
    else:
        item_url = url + "/" + _id

    async with session.get(item_url) as resp:
        if resp.status == 200:
            _json = await resp.json()
            if "value" not in _json:  # 7.0.2+
                _json = {"value": _json}
            _json["id"] = str(_id)
            return _json


async def exists(
    params, session, url, uniquity_keys=None, per_id_url=None, comp_func=None
):
    if not uniquity_keys:
        uniquity_keys = []
    if not per_id_url:
        per_id_url = url

    def default_comp_func(device):
        for k in uniquity_keys:
            if not params.get(k):
                continue
            if isinstance(device, dict):  # 7.0.2 <
                v = device["value"].get(k)
            elif isinstance(device, list):
                v = device
            else:
                raise ModuleFailureException("Unexpect type")

            if isinstance(k, int) or isinstance(v, str):
                k = str(k)
                v = str(v)
            if v == params.get(k):
                return device

    if not comp_func:
        comp_func = default_comp_func

    uniquity_keys += ["label", "pci_slot_number", "sata"]

    devices = await list_devices(session, url)
    full_devices = await build_full_device_list(session, per_id_url, devices)

    for device in full_devices:
        if comp_func(device):
            return device


def set_subkey(root, path, value):
    cur_loc = root
    splitted = path.split("/")
    for j in splitted[:-1]:
        if j not in cur_loc:
            cur_loc[j] = {}
        cur_loc = cur_loc[j]
    cur_loc[splitted[-1]] = value


def prepare_payload(params, payload_format):
    payload = {}
    for i in payload_format["body"].keys():
        if params[i] is None:
            continue

        path = payload_format["body"][i]
        set_subkey(payload, path, params[i])
    return payload


def get_subdevice_type(url):
    """If url needs a subkey, return its name."""
    candidates = []
    for i in url.split("/"):
        if i.startswith("{"):
            candidates.append(i[1:-1])
    if len(candidates) != 2:
        return
    return candidates[-1].split("}")[0]


def get_device_type(url):
    device_type = url.split("/")[-1]
    # NOTE: This mapping can be extracted from the delete end-point of the
    # resource, e.g:
    # /rest/vcenter/vm/{vm}/hardware/ethernet/{nic} -> nic
    # Also, it sounds like we can use "list_index" instead
    if device_type == "ethernet":
        return "nic"
    elif device_type in ["sata", "scsi"]:
        return "adapter"
    elif device_type in ["parallel", "serial"]:
        return "port"
    else:
        return device_type
