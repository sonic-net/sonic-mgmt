#!/bin/bash
set -ex

function show_help_and_exit()
{
    echo "Usage: ${SCRIPT} [options]"
    echo ""
    echo "This script is to merge sonic-mgmt github branch specified by -g to local branch of the sonic-mgmt-int"
    echo "repository specified by -l"
    echo ""
    echo "The merged change will be pushed to the branch specified by -p."
    echo "When the -p option is not specified, the merged change will be pushed to the branch specified by -l."
    echo ""
    echo "When -p is not specified, the script will not push any tags"
    echo ""
    echo "    -h -?              : get this help"
    echo "    -t <token>         : specify the token for accessing the sonic-mgmt-int repository"
    echo "    -g <github branch> : specify branch of the https://github.com/sonic-net/sonic-mgmt repository"
    echo "    -l <local branch>  : specify local branch of the sonic-mgmt-int repository"
    echo "    -p <push branch>   : specify the targed branch of the sonic-mgmt-int repository to be pushed to after merge"
    echo "    -f                 : force push to target branch after merge"
    echo "    -a                 : bypass pushing pre-merge and after-merge tag"

    exit $1
}

function prepare_parameters()
{
    SCRIPT=$0
    TOKEN=""
    GITHUB_BRANCH=""
    LOCAL_BRANCH=""
    PUSH_BRANCH=""
    PUSH_TAG="False"
    FORCE_PUSH="False"
    PRE_MERGE_TAG=""
}

function validate_parameters()
{
    RET=0
    if [[ -z ${TOKEN} || -z ${GITHUB_BRANCH} || -z ${LOCAL_BRANCH} ]]; then
        RET=1
    fi

    if [[ -z ${PUSH_BRANCH} ]]; then
        PUSH_BRANCH=${LOCAL_BRANCH}
    fi

    if [[ ${PUSH_BRANCH} != ${LOCAL_BRANCH} ]]; then
        PUSH_TAG="False"    # Do not push tag when push merged change to stage branch
    fi

    if [[ ${RET} != 0 ]]; then
        show_help_and_exit ${RET}
    fi
}

function prepare_merge()
{
    echo "=== Prepare git branchs for merge ==="
    git config --global user.email "svc-acs@microsoft.com"
    git config --global user.name "Sonic Automation"

    git remote remove github  || true
    git remote remove mssonic || true
    git remote add github  https://github.com/sonic-net/sonic-mgmt
    git remote add mssonic "https://reposync:${TOKEN}@dev.azure.com/mssonic/internal/_git/sonic-mgmt-int"
    git remote remove origin || true

    git fetch github
    git fetch mssonic

    # Checkout a temp branch "foo", so that we can cleanup the branches to be worked on.
    git checkout -b foo mssonic/internal || true

    # Prepare the local branch
    git branch -D ${LOCAL_BRANCH} || true
    git checkout -b ${LOCAL_BRANCH} mssonic/${LOCAL_BRANCH}
    git branch -D foo || true   # cleanup the temp "foo" branch
}

function add_pre_merge_tag()
{
    # Add pre-merge tag
    if [[ x"${PUSH_TAG}" != x"True" ]]; then
        return
    fi

    echo "=== Add pre-merge tag ==="

    curr_tag=`git tag --contains HEAD`
    if [[ -z ${curr_tag} ]]; then
        curr_tag="${LOCAL_BRANCH}-`date '+%Y%m%d-%H%M'`.pre-merge"
        echo "=== Add a tag ${curr_tag} to current ${LOCAL_BRANCH} before merging ==="
        git tag ${curr_tag}
        RC=0
        git push mssonic ${curr_tag} || RC=$?
        if [[ ${RC} != 0 ]]; then
            git tag -d ${curr_tag}
            exit 11
        fi
        PRE_MERGE_TAG=${curr_tag}
    else
        echo "Same pre-merge tag"
    fi
}

function merge_push()
{
    echo "=== Perform merging ==="
    git config pull.rebase false
    RC=0
    git pull github ${GITHUB_BRANCH} --no-edit || RC=$?    # Use git pull to merge from Github
    if [[ ${RC} != 0 ]]; then
        git reset --hard mssonic/${LOCAL_BRANCH} || true
        echo "=== Merging failed, possibly there are conflicts ==="
        exit 12
    fi

    echo "=== Perform pushing from ${LOCAL_BRANCH} to ${PUSH_BRANCH} ==="

    force=""
    if [[ x"${FORCE_PUSH}" == x"True" ]]; then
        force="--force"
    fi

    RC=0
    git push ${force} mssonic HEAD:${PUSH_BRANCH} || RC=$?
    if [[ ${RC} != 0 ]]; then
        git reset --hard mssonic/${LOCAL_BRANCH} || true
        echo "=== Pushing failed ==="
        exit 13
    fi
}

function add_post_merge_tag()
{
    if [[ x"${PUSH_TAG}" != x"True" ]]; then
        return
    fi

    echo "==== Add post-merge tag ===="

    head_tag=`git tag --contains HEAD`

    if [[ ${head_tag} == ${PRE_MERGE_TAG} ]]; then
        echo "=== No change after merging ==="
    else
        post_tag="${LOCAL_BRANCH}-`date '+%Y%m%d-%H%M'`.post-merge"
        echo "=== Add a tag ${post_tag} to branch ${LOCAL_BRANCH} after mergeing ==="
        git tag ${post_tag}
        RC=0
        git push mssonic ${post_tag} || RC=$?   # Add a post-merge tag
        if [[ ${RC} != 0 ]]; then
            git tag -d ${post_tag}
            exit 14
        fi
    fi
}

prepare_parameters

while getopts "h?:t:g:l:p:fa" opt; do
    case ${opt} in
        h|\? )
            show_help_and_exit 0
            ;;
        t )
            TOKEN=${OPTARG}
            ;;
        g )
            GITHUB_BRANCH=${OPTARG}
            ;;
        l )
            LOCAL_BRANCH=${OPTARG}
            ;;
        p )
            PUSH_BRANCH=${OPTARG}
            ;;
        f )
            FORCE_PUSH="True"
            ;;
        a )
            PUSH_TAG="True"
            ;;
    esac
done

validate_parameters
prepare_merge
add_pre_merge_tag
merge_push
add_post_merge_tag

echo "=== Done ==="
