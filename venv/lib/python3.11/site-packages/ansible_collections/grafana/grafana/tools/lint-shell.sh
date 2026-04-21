#!/usr/bin/env bash

source "$(pwd)/tools/includes/utils.sh"

source "./tools/includes/logging.sh"

# output the heading
heading "Grafana Ansible Collection" "Performing Shell Linting using shellcheck"

# check to see if shellcheck is installed
if [[ "$(command -v shellcheck)" = "" ]]; then
  emergency "shellcheck is required if running lint locally, see: (https://shellcheck.net) or run: brew install nvm && nvm install 18";
fi

# determine whether or not the script is called directly or sourced
(return 0 2>/dev/null) && sourced=1 || sourced=0

statusCode=0
while read -r file; do
  shellcheck \
    --external-sources \
    --shell bash \
    --source-path "$(dirname "$file")" \
    "$file"
  currentCode="$?"
  # if the current code is 0, output the file name for logging purposes
  if [[ "$currentCode" == 0 ]]; then
    echo -e "\\x1b[32m$file\\x1b[0m: no issues found"
  else
    echo ""
  fi
  # only override the statusCode if it is 0
  if [[ "$statusCode" == 0 ]]; then
    statusCode="$currentCode"
  fi
done < <(find . -type f -name "*.sh" -not -path "./node_modules/*" -not -path "./.git/*")

echo ""
echo ""

# if the script was called by another, send a valid exit code
if [[ "$sourced" == "1" ]]; then
  return "$statusCode"
else
  exit "$statusCode"
fi
