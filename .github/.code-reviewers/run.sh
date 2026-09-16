#!/bin/bash

# codeowners-cli Documentation
# https://github.com/sonic-net/sonic-pipelines/blob/main/scripts/code-owners/README.md
#


CODEOWNERS_SCRIPTS="/labhome/nmirin/workspace/repo/sonic-pipelines/scripts/code-owners"
# clone from
# https://github.com/sonic-net/sonic-pipelines/


CURRENT_SCRIPT=$(readlink -f "$0")
CODEREVIEWERS_METADIR=$(dirname "${CURRENT_SCRIPT}")
DOT_GITHUB_DIR=$(dirname "${CODEREVIEWERS_METADIR}")
REPO_DIR=$(dirname "${DOT_GITHUB_DIR}")

# Example command
uv --project "${CODEOWNERS_SCRIPTS}" \
      	run codeowners-cli --repo "${REPO_DIR}" \
                      	   --contributors_file "${CODEREVIEWERS_METADIR}/contributors.yaml" \
			   --folder_presets_file "${CODEREVIEWERS_METADIR}/folder_presets.yaml" | tee "${REPO_DIR}/.github/.code-reviewers/pr_reviewer-by-files.yml"
