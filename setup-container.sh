#!/bin/bash

declare -r SCRIPT_NAME="$(basename "${0}")"
declare -r SCRIPT_PATH="$(readlink -f "${0}")"
declare -r SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"

declare -r DOCKER_REGISTRY="sonicdev-microsoft.azurecr.io:443"
declare -r DOCKER_SONIC_MGMT="docker-sonic-mgmt"
declare -r LOCAL_IMAGE_NAME="docker-sonic-mgmt-$(echo "${USER}" | tr '[:upper:]' '[:lower:]')"
declare -r LOCAL_IMAGE_TAG="master"
declare -r LOCAL_IMAGE="${LOCAL_IMAGE_NAME}:${LOCAL_IMAGE_TAG}"

declare -r ROOT_PASS="root"
declare -r USER_PASS="12345"

declare -r HOST_DGNAME="docker"
declare -r HOST_DGID="$(getent group | grep docker | awk -F: '{print $3}')"

declare -r HOST_GID="$(id -g)"
declare -r HOST_UID="$(id -u)"

declare -r ROOT_UID="0"

declare -r EXIT_SUCCESS="0"
declare -r EXIT_FAILURE="1"

declare -r VERBOSE_ERROR="1"
declare -r VERBOSE_NOTICE="3"
declare -r VERBOSE_INFO="4"

declare -r VERBOSE_MAX="${VERBOSE_INFO}"
declare -r VERBOSE_MIN="${VERBOSE_ERROR}"

#
# Arguments -----------------------------------------------------------------------------------------------------------
#

CONTAINER_NAME=""
IMAGE_ID=""
LINK_DIR=""
MOUNT_POINTS="-v \"/var/run/docker.sock:/var/run/docker.sock:rslave\""
VERBOSE_LEVEL="${VERBOSE_MIN}"
SILENT_HOOK="&> /dev/null"

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
    echo "  -i <image_id>        specify Docker image to use. This can be an image ID (hashed value) or an image name."
    echo "                       If no value is provided, defaults to the following images in the specified order:"
    echo "                         1. The local image named \"docker-sonic-mgmt\""
    echo "                         2. The local image named \"sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt\""
    echo "                         3. The remote image at \"sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt\""
    echo "  -d <directory>       specify directory inside container to bind mount to sonic-mgmt root (default: \"/var/src\")"
    echo "  -m <mount_point>     specify directory to bind mount to container"
    echo "  -v                   explain what is being done"
    echo "  -h                   display this help and exit"
    echo
    echo "Examples:"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -i sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -d /var/src"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -m /my/working/dir"
    echo "  ./${SCRIPT_NAME} -h"
    echo
    exit ${1}
}

function show_local_container_login() {
    CONTAINER_EXEC_CMD="docker exec --user root \"${CONTAINER_NAME}\""
    CONTAINER_INTF_CMD="bash -c \"ip -4 route ls | grep 'default' | grep -Po '(?<=dev )(\S+)'\""
    CONTAINER_INTF="$(eval "${CONTAINER_EXEC_CMD} ${CONTAINER_INTF_CMD}")"
    CONTAINER_IPV4_CMD="bash -c \"ip -4 addr show dev \"${CONTAINER_INTF}\" | grep 'inet' | awk '{print \\\$2}' | cut -d'/' -f1\""
    CONTAINER_IPV4="$(eval "${CONTAINER_EXEC_CMD} ${CONTAINER_IPV4_CMD}")"

    echo "******************************************************************************"
    echo "EXEC: docker exec --user ${USER} -ti ${CONTAINER_NAME} bash"
    echo "SSH:  ssh -i ~/.ssh/id_rsa_docker_sonic_mgmt ${USER}@${CONTAINER_IPV4}"
    echo "******************************************************************************"
}

function pull_sonic_mgmt_docker_image() {
    if [[ -z "${IMAGE_ID}" ]]; then
        DOCKER_IMAGES_CMD="docker images --format \"{{.Repository}}:{{.Tag}}\""
        DOCKER_PULL_CMD="docker pull \"${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}\""

        if eval "${DOCKER_IMAGES_CMD}" | grep -q "^${DOCKER_SONIC_MGMT}:latest$"; then
            IMAGE_ID="${DOCKER_SONIC_MGMT}"
        elif eval "${DOCKER_IMAGES_CMD}" | grep -q "^${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}:latest$"; then
            IMAGE_ID="${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}"
        elif log_info "pulling docker image from a registry ..." && eval "${DOCKER_PULL_CMD}"; then
            IMAGE_ID="${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}"
        else
            exit_failure "unable to find a usable default docker image, please specify one manually"
        fi

        log_notice "using default docker image: ${IMAGE_ID}"
    fi
}

function setup_local_image() {
    AUTHKEY_FILE="${HOME}/.ssh/authorized_keys"
    PRIVKEY_FILE="${HOME}/.ssh/id_rsa_docker_sonic_mgmt"
    PUBKEY_FILE="${HOME}/.ssh/id_rsa_docker_sonic_mgmt.pub"

    if [[ ! -f "${PRIVKEY_FILE}" ]]; then
        log_info "generate SSH key pair: $(basename "${PRIVKEY_FILE}")/$(basename "${PUBKEY_FILE}")"
        ssh-keygen -t rsa -q -N "" -f "${PRIVKEY_FILE}" || \
        exit_failure "failed to generate SSH key pair: $(basename "${PRIVKEY_FILE}")/$(basename "${PUBKEY_FILE}")"
    fi

    log_info "read SSH public key: ${PUBKEY_FILE}"
    SSH_PUBKEY="$(cat "${PUBKEY_FILE}")" || \
    exit_failure "failed to read public SSH key: ${PUBKEY_FILE}"

    if [[ -f "${AUTHKEY_FILE}" ]]; then
        grep -q "${SSH_PUBKEY}" "${AUTHKEY_FILE}" || echo "${SSH_PUBKEY}" >> "${AUTHKEY_FILE}"
    else
        cat "${PUBKEY_FILE}" > "${AUTHKEY_FILE}"
        chmod 0644 "${AUTHKEY_FILE}"
    fi

    TMP_DIR="$(mktemp -d)"
    log_info "setup a temporary dir: ${TMP_DIR}"

    log_info "prepare a Dockerfile template: ${TMP_DIR}/Dockerfile.j2"

    cat <<'EOF' > "${TMP_DIR}/Dockerfile.j2"
FROM {{ IMAGE_ID }}

USER root

# Group configuration
RUN if getent group {{ GROUP_NAME }}; \
then groupmod -o -g {{ GROUP_ID }} {{ GROUP_NAME }}; \
else groupadd -o -g {{ GROUP_ID }} {{ GROUP_NAME }}; \
fi

# User configuration
RUN if getent passwd {{ USER_NAME }}; \
then usermod -o -g {{ GROUP_ID }} -u {{ USER_ID }} -m -d /home/{{ USER_NAME }} {{ USER_NAME }}; \
else useradd -o -g {{ GROUP_ID }} -u {{ USER_ID }} -m -d /home/{{ USER_NAME }} -s /bin/bash {{ USER_NAME }}; \
fi

# Docker configuration
RUN if getent group {{ DGROUP_NAME }}; \
then groupmod -o -g {{ DGROUP_ID }} {{ DGROUP_NAME }}; \
else groupadd -o -g {{ DGROUP_ID }} {{ DGROUP_NAME }}; \
fi

# Permissions configuration
RUN usermod -a -G sudo {{ USER_NAME }}
RUN usermod -aG {{ DGROUP_NAME }} {{ USER_NAME }}
RUN echo '{{ USER_NAME }} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{{ USER_NAME }}
RUN chmod 0440 /etc/sudoers.d/{{ USER_NAME }}

# Environment configuration
RUN chown -R '{{ USER_ID }}:{{ GROUP_ID }}' /var/AzDevOps
RUN ln -s /var/AzDevOps/.local/ /root/.local
RUN ln -s /var/AzDevOps/.local/ /home/{{ USER_NAME }}/.local

# SSH/PASS configuration
RUN sed -i -E 's/^#?PermitRootLogin.*$/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN echo 'root:{{ ROOT_PASS }}' | chpasswd
RUN echo '{{ USER_NAME }}:{{ USER_PASS }}' | chpasswd

USER {{ USER_NAME }}

ENV HOME=/home/{{ USER_NAME }}
ENV USER={{ USER_NAME }}

# Passwordless SSH access
RUN mkdir -p ${HOME}/.ssh
RUN chmod 0700 ${HOME}/.ssh
RUN echo '{{ SSH_PUBKEY }}' >> ${HOME}/.ssh/authorized_keys
RUN chmod 0600 ${HOME}/.ssh/authorized_keys

WORKDIR ${HOME}

EOF

    cat <<EOF > "${TMP_DIR}/data.env"
IMAGE_ID=${IMAGE_ID}
DGROUP_NAME=${HOST_DGNAME}
DGROUP_ID=${HOST_DGID}
GROUP_ID=${HOST_GID}
USER_ID=${HOST_UID}
GROUP_NAME=${USER}
USER_NAME=${USER}
USER_PASS=${USER_PASS}
ROOT_PASS=${ROOT_PASS}
SSH_PUBKEY=${SSH_PUBKEY}
EOF

    log_info "generate a Dockerfile: ${TMP_DIR}/Dockerfile"
    j2 -o "${TMP_DIR}/Dockerfile" "${TMP_DIR}/Dockerfile.j2" "${TMP_DIR}/data.env" || \
    log_error "failed to generate a Dockerfile: ${TMP_DIR}/Dockerfile"

    log_info "building docker image from ${TMP_DIR}: ${LOCAL_IMAGE} ..."
    eval "docker build -t \"${LOCAL_IMAGE}\" \"${TMP_DIR}\" ${SILENT_HOOK}" || \
    log_error "failed to build docker image: ${LOCAL_IMAGE}"

    log_info "cleanup a temporary dir: ${TMP_DIR}"
    rm -rf "${TMP_DIR}"

    if ! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${LOCAL_IMAGE}$"; then
        exit_failure "failed to build docker image: ${LOCAL_IMAGE}"
    fi
}

function start_local_container() {
    if docker ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        show_local_container_login
        exit_success "container is already started: ${CONTAINER_NAME}"
    fi

    log_info "creating a container: ${CONTAINER_NAME} ..."

    eval "docker run -d -t \
    -v \"${SCRIPT_DIR}:${LINK_DIR}/sonic-mgmt:rslave\" ${MOUNT_POINTS} \
    --name \"${CONTAINER_NAME}\" \"${LOCAL_IMAGE}\" /bin/bash ${SILENT_HOOK}" || \
    exit_failure "failed to start a container: ${CONTAINER_NAME}"

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
        exit_failure "container name is not set"
    fi

    if [[ -z "${LINK_DIR}" ]]; then
        LINK_DIR="/var/src"
        log_notice "using default bind mount directory: ${LINK_DIR}"
    fi
}

#
# Script --------------------------------------------------------------------------------------------------------------
#

if [[ "$(id -u)" = "${ROOT_UID}" ]]; then
    exit_failure "run as regular user!"
fi

if [[ $# -eq 0 ]]; then
    show_help_and_exit "${EXIT_SUCCESS}"
fi

while getopts "n:i:d:m:vh" opt; do
    case "${opt}" in
        n )
            CONTAINER_NAME="${OPTARG}"
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
        v )
            VERBOSE_LEVEL="${VERBOSE_MAX}"
            SILENT_HOOK=""
            ;;
        h )
            show_help_and_exit "${EXIT_SUCCESS}"
            ;;
        * )
            show_help_and_exit "${EXIT_FAILURE}"
            ;;
    esac
done

parse_arguments

if ! docker info &> /dev/null; then
    exit_failure "unable to access Docker daemon: make sure ${USER} is a member of the docker group"
fi

pull_sonic_mgmt_docker_image
setup_local_image
start_local_container
show_local_container_login

exit_success "sonic-mgmt configuration is done!"
