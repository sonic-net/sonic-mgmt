#!/usr/bin/env bash

source "$(pwd)/tools/includes/utils.sh"

source "./tools/includes/logging.sh"

# output the heading
heading "Grafana Ansible Collection" "Performing Markdown Linting using markdownlint"

# check to see if remark is installed
if [[ ! -f "$(pwd)"/node_modules/.bin/markdownlint-cli2 ]]; then
  emergency "markdownlint-cli2 node module is not installed, please run: make install";
fi

# determine whether or not the script is called directly or sourced
(return 0 2>/dev/null) && sourced=1 || sourced=0

statusCode=0
while read -r dir; do
  info "Checking file/directory: $dir"
  ./node_modules/.bin/markdownlint-cli2-config "$(pwd)/.markdownlint.yaml" "$dir"
  currentCode="$?"
  # if the current code is 0, output the file name for logging purposes
  if [[ "$currentCode" == 0 ]]; then
    echo -e "\\x1b[32m$dir\\x1b[0m: no issues found"
  fi
  # only override the statusCode if it is 0
  if [[ "$statusCode" == 0 ]]; then
    statusCode="$currentCode"
  fi
  echo ""
done < <(find . -type f -name "*.md" -not -path "./node_modules/*" -not -path "./.git/*" -print0 | \
    xargs -0 dirname | \
    sort -nr | \
    uniq | \
    sort | \
    xargs printf -- '%s/*.md\n' | \
    sed 's|\./\*\.md|./README.md|'
  )

echo ""
echo ""

# if the script was called by another, send a valid exit code
if [[ "$sourced" == "1" ]]; then
  return "$statusCode"
else
  exit "$statusCode"
fi
