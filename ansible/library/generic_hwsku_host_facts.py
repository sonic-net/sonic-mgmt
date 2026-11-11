#!/usr/bin/python
"""Read existing host/PTF transport metadata without modifying containers or links."""

import json
import re
import socket
import subprocess


def _read(arguments):
    return json.loads(subprocess.check_output(arguments, stderr=subprocess.PIPE))


def _container_ids(container):
    output = subprocess.check_output(
        ["docker", "container", "ls", "--all", "--filter", "name=^/" + re.escape(container) + "$",
         "--format", "{{.ID}}"], stderr=subprocess.PIPE, text=True)
    return output.splitlines()


def collect(container, external_interface, management=None, inventory_name=None, image_reference=None):
    ids = _container_ids(container)
    if not ids:
        if not image_reference:
            raise ValueError("An absent PTF requires its configured installed image reference")
        images = _read(["docker", "image", "inspect", image_reference])
        if (not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", images[0].get("Id", "")) is None):
            raise ValueError("The configured installed PTF image has no verified immutable identity")
        return {"container": {"name": container, "exists": False, "running": False,
                              "image": image_reference, "image_id": images[0]["Id"]},
                "external_interface": external_interface,
                "host_links": _read(["ip", "-j", "-d", "link", "show"]), "ptf_links": [],
                "requested_management": management or {}, "hostname": socket.gethostname(),
                "inventory_name": inventory_name}
    if len(ids) != 1:
        raise ValueError("The exact baseline PTF name matched more than one container")
    inspected = _read(["docker", "inspect", ids[0]])
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ValueError("Expected exactly one existing baseline PTF container")
    item = inspected[0]
    state = item.get("State", {})
    pid = state.get("Pid")
    running = state.get("Running") is True and type(pid) is int and pid > 1
    result = {
        "container": {"name": container, "exists": True, "id": item["Id"], "image": item["Config"]["Image"],
                      "image_id": item["Image"],
                      "labels": item["Config"].get("Labels", {}), "running": running},
        "external_interface": external_interface,
        "host_links": _read(["ip", "-j", "-d", "link", "show"]),
        "ptf_links": [],
        "requested_management": management or {},
        "hostname": socket.gethostname(), "inventory_name": inventory_name,
    }
    if running:
        result["ptf_links"] = _read(["nsenter", "-t", str(pid), "-n", "ip", "-j", "-d", "link", "show"])
    return result


def main():
    from ansible.module_utils.basic import AnsibleModule
    from generic_hwsku_device_facts import write_private

    module = AnsibleModule(argument_spec={
        "container": {"type": "str", "required": True},
        "external_interface": {"type": "str", "required": True},
        "destination": {"type": "path", "required": True},
        "management": {"type": "dict", "required": True},
        "inventory_name": {"type": "str", "required": True},
        "image_reference": {"type": "str"},
    }, supports_check_mode=True)
    try:
        data = collect(module.params["container"], module.params["external_interface"], module.params["management"],
                       module.params["inventory_name"], module.params["image_reference"])
        if not module.check_mode:
            write_private(module.params["destination"], data)
        module.exit_json(changed=False, ptf_running=data["container"]["running"],
                         message="Host/PTF facts captured; no transport was changed")
    except subprocess.CalledProcessError as error:
        module.fail_json(msg="Host/PTF read-only collection failed with rc {}; output is private".format(
            error.returncode))
    except (OSError, ValueError, KeyError, TypeError, ImportError) as error:
        module.fail_json(msg="Host/PTF read-only collection failed: {}".format(error))


if __name__ == "__main__":
    main()
