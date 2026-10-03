#!/usr/bin/env python3
"""Configure cSONiC PortChannels with an OVS userspace datapath.

The cSONiC container shares the VM host kernel, so teamd cannot create LAGs
when that kernel lacks the team module. This helper replaces only the neighbor
LAG implementation; CONFIG_DB and the normal SONiC control plane remain in use.
"""

import argparse
import os
import re
import subprocess
import time


OVS_SCHEMA = "/usr/share/openvswitch/vswitch.ovsschema"
OVS_DB = "/etc/openvswitch/conf.db"


def call(command, check=True):
    return subprocess.run(command, check=check, text=True,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).stdout.strip()


def config_db_tables():
    from swsscommon import swsscommon

    config_db = swsscommon.ConfigDBConnector()
    config_db.connect()
    return {
        "portchannels": config_db.get_table("PORTCHANNEL"),
        "members": config_db.get_table("PORTCHANNEL_MEMBER"),
        "interfaces": config_db.get_table("PORTCHANNEL_INTERFACE"),
    }


def kernel_member(config_db_member):
    match = re.fullmatch(r"Ethernet(\d+)", config_db_member)
    if not match:
        raise RuntimeError("unsupported cSONiC LAG member {}".format(
            config_db_member))
    return "eth{}".format(match.group(1))


def start_ovs():
    for directory in ("/etc/openvswitch", "/run/openvswitch",
                      "/var/log/openvswitch"):
        os.makedirs(directory, exist_ok=True)

    if not os.path.exists(OVS_DB):
        call(["ovsdb-tool", "create", OVS_DB, OVS_SCHEMA])

    if call(["pgrep", "-x", "ovsdb-server"], check=False) == "":
        call([
            "ovsdb-server",
            "--remote=punix:/run/openvswitch/db.sock",
            "--remote=db:Open_vSwitch,Open_vSwitch,manager_options",
            "--pidfile=/run/openvswitch/ovsdb-server.pid",
            "--detach", "--log-file=/var/log/openvswitch/ovsdb-server.log",
        ])
    call(["ovs-vsctl", "--no-wait", "init"])

    if call(["pgrep", "-x", "ovs-vswitchd"], check=False) == "":
        call([
            "ovs-vswitchd",
            "--pidfile=/run/openvswitch/ovs-vswitchd.pid",
            "--detach", "--log-file=/var/log/openvswitch/ovs-vswitchd.log",
        ])


def stop_teamd():
    for process in ("teamsyncd", "teammgrd", "tlm_teamd"):
        call(["supervisorctl", "stop", process], check=False)


def ovs_portchannel(name, members, mtu, min_links):
    call(["ovs-vsctl", "--if-exists", "del-br", name])
    call(["ip", "link", "del", name], check=False)
    call(["ovs-vsctl", "add-br", name, "--", "set", "Bridge", name,
          "datapath_type=netdev"])

    transaction = ["ovs-vsctl"]
    interface_refs = []
    for index, member in enumerate(members):
        reference = "@member{}".format(index)
        interface_refs.append(reference)
        call(["ip", "link", "set", member, "up"])
        transaction.extend([
            "--", "--id={}".format(reference), "create", "Interface",
            "name={}".format(member),
        ])
    transaction.extend([
        "--", "--id=@bond", "create", "Port",
        "name={}-bond".format(name),
        "interfaces={}".format(",".join(interface_refs)),
        "lacp=active", "bond_mode=balance-slb",
        "other_config:lacp-time=fast",
        "other_config:min-links={}".format(min_links),
        "--", "add", "Bridge", name, "ports", "@bond",
    ])
    call(transaction)
    call(["ip", "link", "set", name, "mtu", str(mtu)])
    call(["ip", "link", "set", name, "up"])


def apply():
    tables = config_db_tables()
    if not tables["portchannels"]:
        print("No cSONiC PortChannels are configured")
        return

    stop_teamd()
    start_ovs()

    for name, attributes in sorted(tables["portchannels"].items()):
        config_members = sorted(
            member for portchannel, member in tables["members"]
            if portchannel == name)
        if not config_members:
            raise RuntimeError("{} has no members".format(name))
        members = [kernel_member(member) for member in config_members]
        ovs_portchannel(name, members, attributes.get("mtu", "9100"),
                        attributes.get("min_links", "1"))

        for key in tables["interfaces"]:
            if isinstance(key, tuple) and key[0] == name:
                call(["ip", "address", "replace", key[1], "dev", name])

        print("Configured {} with userspace OVS members {}".format(
            name, ",".join(members)))


def verify(timeout):
    tables = config_db_tables()
    expected_members = {
        kernel_member(member) for _, member in tables["members"]
    }
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        last = call(["ovs-appctl", "-t", "ovs-vswitchd", "lacp/show"],
                    check=False)
        negotiated = last.count("status: active negotiated")
        attached = {
            match.group(1) for match in re.finditer(
                r"^member: (\S+): current attached$", last, re.MULTILINE)
        }
        if (negotiated == len(tables["portchannels"])
                and expected_members.issubset(attached)):
            print(last)
            return
        time.sleep(2)
    raise RuntimeError("OVS LACP did not converge within {}s:\n{}".format(
        timeout, last))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply", "verify"))
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    if args.action == "apply":
        apply()
    else:
        verify(args.timeout)


if __name__ == "__main__":
    main()
