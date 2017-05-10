#!/bin/bash

# This script updates the SWSSCONFIG_ARGS variable inside the given shell script with the list of files according to given file mask
#
# Usage example:
# to update line
# SWSSCONFIG_ARGS="some_existing.json "
# inside the /usr/bin/start.sh with the all json files located in /etc/swss/config.d/acl/
# execute:
# swssconfig_args_update.sh /usr/bin/start.sh /etc/swss/config.d/acl/*.json'
#
# example of the resulting line:
# SWSSCONFIG_ARGS="some_existing.json acl1.json acl2.json "
#

OLD_LINE=`cat ${1} | grep SWSSCONFIG_ARGS=`
STR_ADD=`ls ${2} | sed 's#.*/##' | tr '\n' ' '`

if echo ${OLD_LINE} | grep -v "${STR_ADD}"; then
    NEW_LINE="${OLD_LINE%\"*}${STR_ADD}\""
    awk -v old_line="${OLD_LINE}" -v new_line="${NEW_LINE}" '{ if ($0 == old_line) print new_line ; else print $0}' ${1} >/tmp/new_conf && mv /tmp/new_conf ${1}
fi
