#!/bin/bash

OLD_LINE=`cat ${1} | grep SWSSCONFIG_ARGS=`
STR_ADD=`ls ${2} | sed 's#.*/##' | tr '\n' ' '`

if echo ${OLD_LINE} | grep -v "${STR_ADD}"; then
    NEW_LINE="${OLD_LINE%\"*}${STR_ADD}\""
    awk -v old_line="${OLD_LINE}" -v new_line="${NEW_LINE}" '{ if ($0 == old_line) print new_line ; else print $0}' ${1} >/tmp/new_conf && mv /tmp/new_conf ${1}
fi
