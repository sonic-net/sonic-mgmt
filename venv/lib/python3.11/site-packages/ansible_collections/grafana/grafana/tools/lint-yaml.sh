#!/usr/bin/env bash

source "$(pwd)/tools/includes/utils.sh"

source "./tools/includes/logging.sh"

# output the heading
heading "Grafana Ansible Collection" "Performing YAML Linting using yamllint"

# make sure pipenv exists
if [[ "$(command -v pipenv)" = "" ]]; then
  echo >&2 "pipenv command is required, see (https://pipenv.pypa.io/en/latest/) or run: brew install pipenv";
  exit 1;
fi

# make sure yamllint exists
if [[ "$(pipenv run pip freeze | grep -c "yamllint")" == "0" ]]; then
  echo >&2 "yamllint command is required, see (https://pypi.org/project/yamllint/). Run \"make install\" to install it.";
  exit 1;
fi

# determine whether or not the script is called directly or sourced
(return 0 2>/dev/null) && sourced=1 || sourced=0

# run yamllint
pipenv run yamllint --strict --config-file "$(pwd)/.yamllint" .
statusCode="$?"

if [[ "$statusCode" == "0" ]]; then
  echo "no issues found"
  echo ""
fi

# if the script was called by another, send a valid exit code
if [[ "$sourced" == "1" ]]; then
  return "$statusCode"
fi
