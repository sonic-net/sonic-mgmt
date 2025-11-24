#!/bin/bash

# codeowners-cli Documentation
# https://github.com/sonic-net/sonic-pipelines/blob/main/scripts/code-owners/README.md
#


CODEOWNERS_SCRIPTS="/labhome/nmirin/workspace/repo/sonic-pipelines/scripts/code-owners"
# clone from
# https://github.com/sonic-net/sonic-pipelines/


CURRENT_SCRIPT=$(readlink -f "$0")
CODEREVIEWERS_METADIR=$(dirname "${CURRENT_SCRIPT}")
REPO_DIR=$(dirname "${CODEREVIEWERS_METADIR}")

cat "${CODEREVIEWERS_METADIR}/CODEREVIEWERS.header"
# Example command
uv --project "${CODEOWNERS_SCRIPTS}" \
      	run codeowners-cli --repo "${REPO_DIR}" \
                      	   --contributors_file "${CODEREVIEWERS_METADIR}/contributors.yaml" \
			   --folder_presets_file "${CODEREVIEWERS_METADIR}/folder_presets.yaml" | tee "${CODEREVIEWERS_METADIR}/CODEREVIEWERS"
