#!/bin/bash -eu

# Script to dual-home the upstream and downstream Collection in a single repo
#
#   This script will build or test a downstream collection, removing any
#   upstream components that will not ship in the downstream release
#
#   NOTES:
#       - All functions are prefixed with f_ so it's obvious where they come
#         from when in use throughout the script

DOWNSTREAM_VERSION="5.0.0"
KEEP_DOWNSTREAM_TMPDIR="${KEEP_DOWNSTREAM_TMPDIR:-''}"
INSTALL_DOWNSTREAM_COLLECTION_PATH="${INSTALL_DOWNSTREAM_COLLECTION_PATH:-}"
_build_dir=""

f_log_info()
{
    printf "%s:LOG:INFO: %s\n" "${0}" "${1}"
}

f_show_help()
{
    printf "Usage: downstream.sh [OPTION]\n"
    printf "\t-s\t\tCreate a temporary downstream release and perform sanity tests.\n"
    printf "\t-u\t\tCreate a temporary downstream release and perform units tests.\n"
    printf "\t-i\t\tCreate a temporary downstream release and perform integration tests.\n"
    printf "\t-m\t\tCreate a temporary downstream release and perform molecule tests.\n"
    printf "\t-b\t\tCreate a downstream release and stage for release.\n"
    printf "\t-r\t\tCreate a downstream release and publish release.\n"
}

f_text_sub()
{
    # Switch FQCN and dependent components
    OKD_sed_files="${_build_dir}/README.md ${_build_dir}/CHANGELOG.rst ${_build_dir}/changelogs/config.yaml ${_build_dir}/ci/downstream.sh ${_build_dir}/galaxy.yml"
    # shellcheck disable=SC2068
    for okd_file in ${OKD_sed_files[@]}; do sed -i.bak "s/OKD/OpenShift/g" "${okd_file}"; done

    sed -i.bak "s/============================/==================================/" "${_build_dir}/CHANGELOG.rst"
    sed -i.bak "s/Ansible Galaxy/Automation Hub/" "${_build_dir}/README.md"
    sed -i.bak "s/community-okd/redhat-openshift/" "${_build_dir}/Makefile"
    sed -i.bak "s/community\/okd/redhat\/openshift/" "${_build_dir}/Makefile"
    sed -i.bak "s/^VERSION\:/VERSION: ${DOWNSTREAM_VERSION}/" "${_build_dir}/Makefile"
    sed -i.bak "s/name\:.*$/name: openshift/" "${_build_dir}/galaxy.yml"
    sed -i.bak "s/namespace\:.*$/namespace: redhat/" "${_build_dir}/galaxy.yml"
    sed -i.bak "s/Kubernetes/OpenShift/g" "${_build_dir}/galaxy.yml"
    sed -i.bak "s/^version\:.*$/version: ${DOWNSTREAM_VERSION}/" "${_build_dir}/galaxy.yml"
    sed -i.bak "/STARTREMOVE/,/ENDREMOVE/d" "${_build_dir}/README.md"
    sed -i.bak "s/[[:space:]]okd:$/ openshift:/" "${_build_dir}/meta/runtime.yml"

    find "${_build_dir}" -type f ! -name galaxy.yml -exec sed -i.bak "s/community\.okd/redhat\.openshift/g" {} \;
    find "${_build_dir}" -type f ! -name galaxy.yml -exec sed -i.bak "s/group\/redhat\.openshift\.okd/redhat\.openshift\.openshift/g" {} \;
    find "${_build_dir}" -type f -name "*.bak" -delete
}

f_prep()
{
    f_log_info "${FUNCNAME[0]}"
    # Array of excluded files from downstream build (relative path)
    _file_exclude=(
    )

    # Files to copy downstream (relative repo root dir path)
    _file_manifest=(
        .gitignore
        CHANGELOG.rst
        galaxy.yml
        LICENSE
        README.md
        Makefile
        .yamllint
        requirements.txt
        requirements.yml
        test-requirements.txt
    )

    # Directories to recursively copy downstream (relative repo root dir path)
    _dir_manifest=(
        .config
        changelogs
        ci
        meta
        molecule
        plugins
        tests
    )

    # Temp build dir
    _tmp_dir=$(mktemp -d)
    _start_dir="${PWD}"
    _build_dir="${_tmp_dir}/ansible_collections/redhat/openshift"
    mkdir -p "${_build_dir}"
}


f_cleanup()
{
    f_log_info "${FUNCNAME[0]}"
    if [[ -n "${_build_dir}" ]]; then
        if [[ -n ${KEEP_DOWNSTREAM_TMPDIR} ]]; then
            if [[ -d ${_build_dir} ]]; then
                rm -fr "${_build_dir}"
            fi
        fi
    else
        exit 0
    fi
}

# Exit and handle cleanup processes if needed
f_exit()
{
    f_cleanup
    exit "$0"
}

f_create_collection_dir_structure()
{
    f_log_info "${FUNCNAME[0]}"
    # Create the Collection
    for f_name in "${_file_manifest[@]}";
    do
        cp "./${f_name}" "${_build_dir}/${f_name}"
    done
    for d_name in "${_dir_manifest[@]}";
    do
        cp -r "./${d_name}" "${_build_dir}/${d_name}"
    done
    if [ -n "${_file_exclude:-}" ]; then
        for exclude_file in "${_file_exclude[@]}";
        do
            if [[ -f "${_build_dir}/${exclude_file}" ]]; then
                rm -f "${_build_dir}/${exclude_file}"
            fi
        done
    fi
}

f_handle_doc_fragments_workaround()
{
    f_log_info "${FUNCNAME[0]}"
    local install_collections_dir="${_build_dir}/collections/"
    local temp_fragments_json="${_tmp_dir}/fragments.json"
    local temp_start="${_tmp_dir}/startfile.txt"
    local temp_end="${_tmp_dir}/endfile.txt"
    local rendered_fragments="./rendereddocfragments.txt"

    # FIXME: Check Python interpreter from environment variable to work with prow
    PYTHON=${DOWNSTREAM_BUILD_PYTHON:-/usr/bin/python3}
    f_log_info "Using Python interpreter: ${PYTHON}"

    # Modules with inherited doc fragments from kubernetes.core that need
    # rendering to deal with Galaxy/AH lack of functionality.
    # shellcheck disable=SC2207
    _doc_fragment_modules=($("${PYTHON}" "${_start_dir}/ci/doc_fragment_modules.py" -c "${_start_dir}"))

    # Build the collection, export docs, render them, stitch it all back together
    pushd "${_build_dir}" || return
        ansible-galaxy collection build
        ansible-galaxy collection install --force-with-deps -p "${install_collections_dir}" ./*.tar.gz
        rm ./*.tar.gz
        for doc_fragment_mod in "${_doc_fragment_modules[@]}"
        do
            local module_py="plugins/modules/${doc_fragment_mod}.py"
            f_log_info "Processing doc fragments for ${module_py}"
            # We need following variable for ansible-doc only
            # shellcheck disable=SC2097,SC2098
            ANSIBLE_COLLECTIONS_PATH="${install_collections_dir}" \
            ANSIBLE_COLLECTIONS_PATHS="${ANSIBLE_COLLECTIONS_PATH}:${install_collections_dir}" \
                ansible-doc -j "redhat.openshift.${doc_fragment_mod}" > "${temp_fragments_json}"
            "${PYTHON}" "${_start_dir}/ci/downstream_fragments.py" "redhat.openshift.${doc_fragment_mod}" "${temp_fragments_json}"
            sed -n '/STARTREMOVE/q;p' "${module_py}" > "${temp_start}"
            sed '1,/ENDREMOVE/d' "${module_py}" > "${temp_end}"
            cat "${temp_start}" "${rendered_fragments}" "${temp_end}" > "${module_py}"
        done
        rm -f "${rendered_fragments}"
        rm -fr "${install_collections_dir}"
    popd

}

f_copy_collection_to_working_dir()
{
    f_log_info "${FUNCNAME[0]}"
    # Copy the Collection build result into original working dir
    f_log_info "copying built collection *.tar.gz into ./"
    cp "${_build_dir}"/*.tar.gz ./
    # Install downstream collection into provided path
    if [[ -n ${INSTALL_DOWNSTREAM_COLLECTION_PATH} ]]; then
        f_log_info "Install built collection *.tar.gz into ${INSTALL_DOWNSTREAM_COLLECTION_PATH}"
        ansible-galaxy collection install -p "${INSTALL_DOWNSTREAM_COLLECTION_PATH}" "${_build_dir}"/*.tar.gz
    fi
    rm -f "${_build_dir}"/*.tar.gz
}

f_common_steps()
{
    f_log_info "${FUNCNAME[0]}"
    f_prep
    f_create_collection_dir_structure
    f_text_sub
    f_handle_doc_fragments_workaround
}

# Run the test sanity scanerio
f_test_sanity_option()
{
    f_log_info "${FUNCNAME[0]}"
    f_common_steps
    pushd "${_build_dir}" || return
        if command -v docker &> /dev/null
            then
                make sanity
            else
                SANITY_TEST_ARGS="--venv --color" make sanity
            fi
        f_log_info "SANITY TEST PWD: ${PWD}"
        make sanity
    popd || return
    f_cleanup
}

# Run the test integration
f_test_integration_option()
{
    f_log_info "${FUNCNAME[0]}"
    f_common_steps
    pushd "${_build_dir}" || return
        f_log_info "INTEGRATION TEST WD: ${PWD}"
        make molecule
    popd || return
    f_cleanup
}

# Run the test units
f_test_units_option()
{
    f_log_info "${FUNCNAME[0]}"
    f_common_steps
    pushd "${_build_dir}" || return
        if command -v docker &> /dev/null
            then
                make units
            else
                UNITS_TEST_ARGS="--venv --color" make units
            fi
        f_log_info "UNITS TEST PWD: ${PWD}"
        make units
    popd || return
    f_cleanup
}

# Run the build scanerio
f_build_option()
{
    f_log_info "${FUNCNAME[0]}"
    f_common_steps
    pushd "${_build_dir}" || return
        f_log_info "BUILD WD: ${PWD}"
        make build
    popd || return
    f_copy_collection_to_working_dir
    f_cleanup
}

# If no options are passed, display usage and exit
if [[ "${#}" -eq "0" ]]; then
    f_show_help
    f_exit 0
fi

# Handle options
while getopts ":siurb" option
do
  case $option in
    s)
        f_test_sanity_option
        ;;
    i)
        f_test_integration_option
        ;;
    u)
        f_test_units_option
        ;;
    r)
        f_release_option
        ;;
    b)
        f_build_option
        ;;
    *)
        printf "ERROR: Unimplemented option chosen.\n"
        f_show_help
        f_exit 1
        ;;   # Default.
  esac
done

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
