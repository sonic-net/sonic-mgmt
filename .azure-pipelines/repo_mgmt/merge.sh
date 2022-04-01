#!/bin/bash
set -e

usage="Usage: merge.sh <github_branch> <mssonic_branch> <mssonic_token>"

github_branch=$1
mssonic_branch=$2
mssonic_token=$3

if [[ -z ${github_branch} || -z ${mssonic_branch} || -z ${mssonic_token} ]]; then
    echo ${usage}
    exit 10
fi

echo "=== Merging branch -${github_branch}- -${mssonic_branch}- ... ==="

git config --global user.email "svc-acs@microsoft.com"
git config --global user.name "Sonic Automation"

git remote remove github  || true
git remote remove mssonic || true
git remote add github  https://github.com/Azure/sonic-mgmt
git remote add mssonic "https://reposync:${mssonic_token}@dev.azure.com/mssonic/internal/_git/sonic-mgmt-int"
git remote remove origin || true

git fetch github
git fetch mssonic

# Checkout a temp branch "foo", so that we can cleanup the branches to be worked on.
git checkout -b foo mssonic/internal || true

# Prepare the local mssonic_branch
git branch -D ${mssonic_branch} || true
git checkout -b ${mssonic_branch} mssonic/${mssonic_branch}
git branch -D foo || true   # cleanup the temp "foo" branch

# Add pre-merge tag
curr_tag=`git tag --contains HEAD`
if [[ -z ${curr_tag} ]]; then
    curr_tag="${mssonic_branch}-`date '+%Y%m%d-%H%M'`.pre-merge"
    echo "Add a tag ${curr_tag} to current ${mssonic_branch} before rebasing ..."
    git tag ${curr_tag}
    RC=0
    git push mssonic ${curr_tag} || RC=$?
    if [[ ${RC} != 0 ]]; then
        git tag -d ${curr_tag}
        exit 11
    fi
fi

post_tag="${mssonic_branch}-`date '+%Y%m%d-%H%M'`.post-merge"

# Perform merge
git config pull.rebase false
RC=0
git pull github ${github_branch} --no-edit || RC=$?    # Use git pull to merge from Github
if [[ ${RC} != 0 ]]; then
    git reset --hard mssonic/${mssonic_branch} || true
    echo "=== Merging failed, possibly there are conflicts ==="
    exit 12
fi

head_tag=`git tag --contains HEAD`

if [[ ${head_tag} == ${curr_tag} ]]; then
    echo "=== No change after merging ==="
else
    post_tag="${mssonic_branch}-`date '+%Y%m%d-%H%M'`.post-merge"
    echo "=== Add a tag ${post_tag} to current ${mssonic_branch} after merging ... ==="
    git tag ${post_tag}
    RC=0
    git push mssonic ${post_tag} || RC=$?   # Add a post-merge tag
    if [[ ${RC} != 0 ]]; then
        git tag -d ${post_tag}
        exit 13
    fi
    git push mssonic HEAD:${mssonic_branch}      # Push the merged commits to mssonic
fi
