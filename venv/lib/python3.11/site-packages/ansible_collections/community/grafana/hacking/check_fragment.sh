#!/usr/bin/env bash

function fail() {
	cat <<EOF
    Dear contributor,

    Thank you for you Pull Request !
    To ease the work of maintainers you need to add a [changelog fragment](https://docs.ansible.com/ansible/latest/community/development_process.html#creating-a-changelog-fragment) in you PR.

    It will help your change be released faster !
    Thank you !
EOF
	exit 1
}

FRAGMENTS=$(git fetch && git diff --name-only --diff-filter=ACMRT origin/main..HEAD | grep "changelogs")
[ -z "$FRAGMENTS" ] && fail
exit 0
