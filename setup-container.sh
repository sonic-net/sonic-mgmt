#!/bin/bash

declare -r SCRIPT_NAME="$(basename "${0}")"
declare -r SCRIPT_PATH="$(readlink -f "${0}")"
declare -r SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"

declare -r DOCKER_REGISTRY="sonicdev-microsoft.azurecr.io:443"
declare -r DOCKER_SONIC_MGMT="docker-sonic-mgmt:latest"

declare -r ROOT_PASS="root"
declare -r USER_PASS="12345"

declare -r HOST_DGNAME="docker"
declare -r HOST_DGID="$(getent group docker | awk -F: '{print $3}')"

declare -r HOST_GID="$(id -g)"
declare -r HOST_UID="$(id -u)"

declare -r ROOT_UID="0"

declare -r YES_PARAM="yes"
declare -r NO_PARAM="no"

declare -r EXIT_SUCCESS="0"
declare -r EXIT_FAILURE="1"

declare -r VERBOSE_ERROR="1"
declare -r VERBOSE_NOTICE="3"
declare -r VERBOSE_INFO="4"

declare -r VERBOSE_MAX="${VERBOSE_INFO}"
declare -r VERBOSE_MIN="${VERBOSE_ERROR}"

declare EXISTING_CONTAINER_NAME=""

#
# Arguments -----------------------------------------------------------------------------------------------------------
#

ENV_VARS=""
CONTAINER_NAME=""
IMAGE_ID=""
LINK_DIR=""
MOUNT_POINTS="-v \"/var/run/docker.sock:/var/run/docker.sock:rslave\""
PUBLISH_PORTS=""
FORCE_REMOVAL="${NO_PARAM}"
VERBOSE_LEVEL="${VERBOSE_MIN}"
SILENT_HOOK="&> /dev/null"
ENABLE_DEBUG=0

# Sonic-mgmt remote debug feature
DEBUG_PORT_START_RANGE=50000
DEBUG_PORT_END_RANGE=60000
DEFAULT_LOCK_FOLDER="/tmp/sonic-mgmt-locks/"

#
# Functions -----------------------------------------------------------------------------------------------------------
#

function log_error() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_ERROR}" ]]; then
        echo "ERROR: $*"
    fi
}

function log_notice() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_NOTICE}" ]]; then
        echo "NOTICE: $*"
    fi
}

function log_info() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_INFO}" ]]; then
        echo "INFO: $*"
    fi
}

function exit_failure() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_ERROR}" ]]; then
        echo
        log_error "$@"
        echo
    fi

    exit "${EXIT_FAILURE}"
}

function exit_success() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_INFO}" ]]; then
        echo
        log_info "$@"
        echo
    fi

    exit "${EXIT_SUCCESS}"
}

function show_help_and_exit() {
    echo "Usage ./${SCRIPT_NAME} [OPTIONS]"
    echo
    echo "Mandatory options:"
    echo "  -n <container_name>  set the name of the Docker container"
    echo
    echo "Other options:"
    echo "  -e <VAR=value>      set environment variable inside the container (can be used multiple times)"
    echo "  -i <image_id>        specify Docker image to use. This can be an image ID (hashed value) or an image name."
    echo "                       If no value is provided, defaults to the following images in the specified order:"
    echo "                         1. The local image named \"docker-sonic-mgmt\""
    echo "                         2. The remote image at \"sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest\""
    echo "  -d <directory>       specify directory inside container to bind mount to sonic-mgmt root (default: \"/var/src\")"
    echo "  -m <mount_point>     specify directory to bind mount to container"
    echo "  -p <port>            publish container port to the host"
    echo "  -f                   automatically remove the container when it exits"
    echo "  -v                   explain what is being done"
    echo "  -x                   show execution details"
    echo "  -h                   display this help and exit"
    echo "  --enable-debug       enable debug mode"
    echo
    echo "Examples:"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -i sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -d /var/src"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -m /my/working/dir"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -p 192.0.2.1:8080:80/tcp"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master --enable-debug"
    echo "  ./${SCRIPT_NAME} -h"
    echo
    exit ${1}
}

function show_local_container_login() {
    local CONTAINER_IPV4
    CONTAINER_IPV4="$(docker exec --user root "${CONTAINER_NAME}" \
        bash -c "ip -4 route get 1 | grep -Po '(?<=src )(\S+)'")"

    echo "******************************************************************************"
    echo "EXEC: docker exec --user ${USER} -ti ${CONTAINER_NAME} bash"
    echo "SSH:  ssh -i ~/.ssh/id_ed25519_docker_sonic_mgmt ${USER}@${CONTAINER_IPV4}"
    echo "******************************************************************************"

    if [[ -n "${SELECTED_DEBUG_PORT}" ]]; then
        echo
        echo "*********************************[IMPORTANT]*********************************"
        echo "DEBUG PORT: $SELECTED_DEBUG_PORT"
        echo "Please use the above debug port in your vscode extensions"
        echo "When running the test, add --enable-debug to the end of your ./run_tests.sh to use"
        echo "You can check which port was assigned to you again by running 'docker ps' and search for your container"
        echo "*********************************[IMPORTANT]*********************************"
    fi
}

function pull_sonic_mgmt_docker_image() {
    if [[ -z "${IMAGE_ID}" ]]; then
        if docker image inspect "${DOCKER_SONIC_MGMT}" &> /dev/null; then
            IMAGE_ID="${DOCKER_SONIC_MGMT}"
        elif log_info "pulling docker image from a registry ..." && docker pull "${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}"; then
            IMAGE_ID="${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}"
        else
            exit_failure "unable to find a usable default docker image, please specify one manually"
        fi

        log_notice "using default docker image: ${IMAGE_ID}"
    fi
}

PRIVKEY_FILE="${HOME}/.ssh/id_ed25519_docker_sonic_mgmt"
PUBKEY_FILE="${HOME}/.ssh/id_ed25519_docker_sonic_mgmt.pub"

function generate_ssh_keys() {
    local AUTHKEY_FILE="${HOME}/.ssh/authorized_keys"

    if [[ ! -f "${PRIVKEY_FILE}" ]]; then
        log_info "generate SSH key pair: $(basename "${PRIVKEY_FILE}")/$(basename "${PUBKEY_FILE}")"
        ssh-keygen -t ed25519 -q -N "" -f "${PRIVKEY_FILE}" || \
        exit_failure "failed to generate SSH key pair: $(basename "${PRIVKEY_FILE}")/$(basename "${PUBKEY_FILE}")"
    fi

    log_info "read SSH public key: ${PUBKEY_FILE}"
    SSH_PUBKEY="$(cat "${PUBKEY_FILE}")" || \
    exit_failure "failed to read public SSH key: ${PUBKEY_FILE}"

    if [[ -f "${AUTHKEY_FILE}" ]]; then
        grep -q "${SSH_PUBKEY}" "${AUTHKEY_FILE}" || echo "${SSH_PUBKEY}" >> "${AUTHKEY_FILE}"
    else
        echo "${SSH_PUBKEY}" > "${AUTHKEY_FILE}"
        chmod 0600 "${AUTHKEY_FILE}"
    fi
}

function configure_container_user() {
    log_info "configuring user ${USER} inside container ..."

    # Write setup script to a temp file; host-side variables are substituted by the heredoc.
    # Variables that must survive as literals inside the container (e.g. loop vars, sed anchors)
    # are escaped with \$ so they reach the container shell unexpanded.
    local TMP_SETUP
    TMP_SETUP="$(mktemp)"
    trap "rm -f '${TMP_SETUP}'" RETURN
    cat > "${TMP_SETUP}" << SETUP_EOF
#!/bin/bash
set -e

# Remove default ubuntu user if present (Ubuntu 24.04)
getent passwd ubuntu && userdel -r ubuntu || true

# Group configuration: reuse whichever group already owns the host GID, or create a new one.
# This avoids groupmod/groupadd failures from duplicate GIDs (e.g. systemd-network sharing a GID).
user_group=\$(getent group ${HOST_GID} | awk -F: '{print \$1}')
if [ -z "\$user_group" ]; then
    if getent group ${USER}; then
        groupmod -g ${HOST_GID} ${USER}
    else
        groupadd -g ${HOST_GID} ${USER}
    fi
    user_group=${USER}
fi

# User configuration
# useradd -l works around https://github.com/moby/moby/issues/5419 for large UIDs
if getent passwd ${USER}; then
    userdel ${USER}
fi
useradd -l -g "\$user_group" -u ${HOST_UID} -m -d /home/${USER} -s /bin/bash ${USER}

# Docker socket access: find the group owning the host docker GID, or create it.
# Using the existing group (regardless of name) is safe since socket access depends on GID only.
docker_group=\$(getent group ${HOST_DGID} | awk -F: '{print \$1}')
if [ -z "\$docker_group" ]; then
    if getent group ${HOST_DGNAME}; then
        groupmod -g ${HOST_DGID} ${HOST_DGNAME}
    else
        groupadd -g ${HOST_DGID} ${HOST_DGNAME}
    fi
    docker_group=${HOST_DGNAME}
fi

# Copy AzDevOps environment baseline (skip python virtual envs)
if [ '${USER}' != 'AzDevOps' ]; then
    /bin/bash -O extglob -c 'cp -a -f /var/AzDevOps/!(env-*) /home/${USER}/ 2>/dev/null || true'
    for hidden_stuff in .profile .local .ssh; do
        cp -a -f "/var/AzDevOps/\${hidden_stuff}" /home/${USER}/ 2>/dev/null || true
    done
fi

# Permissions configuration
usermod -a -G sudo ${USER}
usermod -a -G "\$docker_group" ${USER}
echo '${USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/${USER}
chmod 0440 /etc/sudoers.d/${USER}
chown -R ${HOST_UID}:${HOST_GID} /home/${USER}

# SSH/password configuration
sed -i -E 's/^#?PermitRootLogin.*\$/PermitRootLogin yes/g' /etc/ssh/sshd_config
echo 'root:${ROOT_PASS}' | chpasswd
echo '${USER}:${USER_PASS}' | chpasswd

# SSH key setup
mkdir -p /home/${USER}/.ssh
cat /tmp/ssh_pubkey_to_add >> /home/${USER}/.ssh/authorized_keys
mv /tmp/id_ed25519 /home/${USER}/.ssh/id_ed25519
mv /tmp/id_ed25519.pub /home/${USER}/.ssh/id_ed25519.pub
chmod 0700 /home/${USER}/.ssh
chmod 0600 /home/${USER}/.ssh/id_ed25519
chmod 0644 /home/${USER}/.ssh/id_ed25519.pub
chmod 0600 /home/${USER}/.ssh/authorized_keys
chown -R ${HOST_UID}:${HOST_GID} /home/${USER}/.ssh
SETUP_EOF

    docker cp "${TMP_SETUP}" "${CONTAINER_NAME}:/tmp/setup_user.sh"
    docker cp "${PRIVKEY_FILE}" "${CONTAINER_NAME}:/tmp/id_ed25519"
    docker cp "${PUBKEY_FILE}" "${CONTAINER_NAME}:/tmp/id_ed25519.pub"
    echo "${SSH_PUBKEY}" | docker exec -i --user root "${CONTAINER_NAME}" tee /tmp/ssh_pubkey_to_add > /dev/null
    rm -f "${TMP_SETUP}"
    trap - RETURN

    eval "docker exec --user root \"${CONTAINER_NAME}\" bash /tmp/setup_user.sh ${SILENT_HOOK}" || \
        exit_failure "failed to configure user in container"

    if [[ -n "${SELECTED_DEBUG_PORT}" ]]; then
        eval "docker exec --user root \"${CONTAINER_NAME}\" \
            bash -c \"echo 'export SONIC_MGMT_DEBUG_PORT=${SELECTED_DEBUG_PORT}' >> /home/${USER}/.profile\" \
            ${SILENT_HOOK}"
    fi
}

function container_exists() {
    local count
    count=$(docker ps --all --filter "name=^${CONTAINER_NAME}$" --format '{{.ID}}' | wc -l)
    [[ "$count" -gt 0 ]]
}

function get_existing_container() {
    local container_ids
    mapfile -t container_ids < <(docker container ls --all --filter="ancestor=${IMAGE_ID}" --format '{{.ID}}')
    local count=${#container_ids[@]}
    case $count in
        0)
            EXISTING_CONTAINER_NAME=""
            ;;
        1)
            local container_name
            container_name=$(docker inspect "${container_ids[0]}" --format '{{.Name}}')
            EXISTING_CONTAINER_NAME="${container_name#/}"
            ;;
        *)
            echo "Multiple container IDs found: ${container_ids[*]}"
            EXISTING_CONTAINER_NAME=""
            ;;
    esac
}

function start_local_container() {

    if container_exists
    then
        log_info "starting existing container ${CONTAINER_NAME} ..."
        docker start "${CONTAINER_NAME}"
    else
        log_info "creating a container: ${CONTAINER_NAME} ..."
        eval "docker run --cap-add=SYS_PTRACE -d -t ${PUBLISH_PORTS} ${ENV_VARS} -h ${CONTAINER_NAME} \
        -v \"$(dirname "${SCRIPT_DIR}"):${LINK_DIR}:rslave\" ${MOUNT_POINTS} \
        --name \"${CONTAINER_NAME}\" \"${IMAGE_ID}\" /bin/bash ${SILENT_HOOK}" || \
        exit_failure "failed to start a container: ${CONTAINER_NAME}"

        configure_container_user
    fi

    eval "docker exec --user root \"${CONTAINER_NAME}\" \
    bash -c \"service ssh restart\" ${SILENT_HOOK}" || \
    exit_failure "failed to start SSH service"

    log_info "verifying UID and GID in container matches host"
    CONTAINER_GID="$(docker exec "${CONTAINER_NAME}" bash -c "id ${USER} -g")"
    CONTAINER_UID="$(docker exec "${CONTAINER_NAME}" bash -c "id ${USER} -u")"

    if [[ "${HOST_GID}" != "${CONTAINER_GID}" ]]; then
        exit_failure "group ID mismatch between host and container"
    fi

    if [[ "${HOST_UID}" != "${CONTAINER_UID}" ]]; then
        exit_failure "user ID mismatch between host and container"
    fi
}

function parse_arguments() {

    if [[ -z "${CONTAINER_NAME}" ]]; then
        get_existing_container
    if [[ -z "${EXISTING_CONTAINER_NAME}" ]]
        then
            exit_failure "container name is not set."
        else
            exit_failure "found existing container (\"docker start $EXISTING_CONTAINER_NAME\")"
        fi
    else
        # If container name is over 64 characters, container will not be able to start due to hostname limitation
        container_name_len=${#CONTAINER_NAME}
        if [ "$container_name_len" -gt "64" ]; then
            exit_failure "Length of supplied container name exceeds 64 characters (currently $container_name_len chars)"
        fi
    fi

    if [[ -z "${LINK_DIR}" ]]; then
        LINK_DIR="/var/src"
        log_notice "using default bind mount directory: ${LINK_DIR}"
    fi
}

function find_debug_port() {
    mkdir -p "$DEFAULT_LOCK_FOLDER"
    for port in $(seq $DEBUG_PORT_START_RANGE $DEBUG_PORT_END_RANGE); do
        if ! ss -tuln | grep -q ":$port\b" && mkdir $DEFAULT_LOCK_FOLDER/$port.lock 2>/dev/null; then
            trap "rm -rf $DEFAULT_LOCK_FOLDER/$port.lock" EXIT # Remove the port.lock file when done
            SELECTED_DEBUG_PORT=$port
            return 0
        fi
    done
    return 1
}


ARGS=()
for arg in "$@"; do
    if [[ "$arg" == "--enable-debug" ]]; then
        ENABLE_DEBUG=1
    else
        ARGS+=("$arg")
    fi
done

set -- "${ARGS[@]}"
#
# Script --------------------------------------------------------------------------------------------------------------
#

if [[ $# -eq 0 ]]; then
    show_help_and_exit "${EXIT_SUCCESS}"
fi

while getopts "e:n:i:d:m:p:fvxh" opt; do
    case "${opt}" in
        n )
            CONTAINER_NAME="${OPTARG}"
            ;;
        e )
            ENV_VARS+=" -e ${OPTARG}"
            ;;
        i )
            IMAGE_ID="${OPTARG}"
            ;;
        d )
            LINK_DIR="${OPTARG}"
            ;;
        m )
            MOUNT_POINTS+=" -v \"${OPTARG}:${OPTARG}:rslave\""
            ;;
        p )
            PUBLISH_PORTS+=" -p \"${OPTARG}\""
            ;;
        f )
            FORCE_REMOVAL="${YES_PARAM}"
            ;;
        v )
            VERBOSE_LEVEL="${VERBOSE_MAX}"
            SILENT_HOOK=""
            ;;
        x )
            set -x
            ;;
        h )
            show_help_and_exit "${EXIT_SUCCESS}"
            ;;
        * )
            show_help_and_exit "${EXIT_FAILURE}"
            ;;
    esac
done

if [[ "$ENABLE_DEBUG" -eq 1 ]]; then
    find_debug_port
    if [[ -n "$SELECTED_DEBUG_PORT" ]]; then
        PUBLISH_PORTS+=" -p \"$SELECTED_DEBUG_PORT:$SELECTED_DEBUG_PORT\""
    else
        echo "FAILURE: Cannot find an eligible debug port within the range [$DEBUG_PORT_START_RANGE, $DEBUG_PORT_END_RANGE]"
        echo "Please re-run without --enable-debug option."
        exit 1
    fi
fi

parse_arguments

if [[ "$(id -u)" = "${ROOT_UID}" ]]; then
    exit_failure "run as regular user!"
fi

if ! docker info &> /dev/null; then
    exit_failure "unable to access Docker daemon: make sure ${USER} is a member of the docker group"
fi

if docker ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    if [[ "${FORCE_REMOVAL}" = "${YES_PARAM}" ]]; then
        log_notice "removing existing container as requested: ${CONTAINER_NAME}"
        eval "docker rm -f \"${CONTAINER_NAME}\" ${SILENT_HOOK}"
    else
        show_local_container_login
        exit_success "container already exists: ${CONTAINER_NAME}"
    fi
fi

pull_sonic_mgmt_docker_image
generate_ssh_keys
start_local_container
show_local_container_login

exit_success "sonic-mgmt configuration is done!"
