#!/usr/bin/env bash

set -e;
set -u;

rm -f /root/mongodb_selinux.success;
checkmodule -M -m -o /root/mongodb_cgroup_memory.mod /root/mongodb_cgroup_memory.te
semodule_package -o /root/mongodb_cgroup_memory.pp -m /root/mongodb_cgroup_memory.mod
semodule -i /root/mongodb_cgroup_memory.pp
touch /root/mongodb_selinux.success;