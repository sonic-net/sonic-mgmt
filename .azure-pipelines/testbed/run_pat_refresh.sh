#!/bin/bash

# A wrapper script to invoke the pat-refresh playbook

echo "PWD = ${PWD}"
KEY="${1}"
PAT=${AZ_REPO_PAT}
cd ansible && ansible-playbook -i ${KEY} -e "PAT=${PAT}" pat_refresh.yml