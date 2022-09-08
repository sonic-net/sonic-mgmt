#!/bin/bash
declare -r HOSTNAME=$(hostname)

#Check if it's on a right place to setup the container
if [[ ${host} != *"netdev"* ]]; then 
    echo "This script only support netdev device only!!!"; 
fi

declare -r SCRIPT_NAME="$(basename "${0}")"
declare -r SCRIPT_PATH="$(readlink -f "${0}")"
declare -r SCRIPT_DIR="$(pwd)"

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

declare -r YES_PARAM="yes"
declare -r NO_PARAM="no"

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
MOUNT_POINTS="-v \"/var/run/docker.sock:/var/run/docker.sock:rslave\" \
-v \"/etc/ssl/certs:/etc/ssl/certs\" \
-v \"/etc/ssl/private:/etc/ssl/private\" \
-v \"/usr/local/share/ca-certificates:/usr/local/share/ca-certificates\" \
-v \"/etc/kusto/secrets:/etc/kusto/secrets\" \
-v \"/etc/phynet_credentials/secrets:/etc/phynet_credentials/secrets\" \
-v \"/usr/local/lib/dsts:/usr/local/lib/dsts\" \
-v \"/usr/local/lib/dsts2:/usr/local/lib/dsts2\""
PUBLISH_PORTS=""
FORCE_REMOVAL="${NO_PARAM}"
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
    echo "  -p <port>            publish container port to the host"
    echo "  -f                   automatically remove the container when it exits"
    echo "  -v                   explain what is being done"
    echo "  -x                   show execution details"
    echo "  -h                   display this help and exit"
    echo
    echo "Examples:"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -i sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -d /var/src"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -m /my/working/dir"
    echo "  ./${SCRIPT_NAME} -n sonic-mgmt-${USER}_master -p 192.0.2.1:8080:80/tcp"
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
    echo "EXEC: docker exec --user root -ti ${CONTAINER_NAME} bash"
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

function start_local_container() {
    log_info "creating a container: ${CONTAINER_NAME} ..."

    eval "docker run --user root -d -t ${PUBLISH_PORTS} \
    -v \"$(dirname "${SCRIPT_DIR}"):${LINK_DIR}:rslave\" ${MOUNT_POINTS} \
    --name \"${CONTAINER_NAME}\" \"${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}:latest\" /bin/bash ${SILENT_HOOK}" || \
    exit_failure "failed to start a container: ${CONTAINER_NAME}"

    eval "docker exec --user root \"${CONTAINER_NAME}\" \
    bash -c \"sed -i -E 's/^#?PermitRootLogin.*$/PermitRootLogin yes/g' /etc/ssh/sshd_config\"" || \
    exit_failure "failed to set allow root SSH"

    eval "docker exec --user root \"${CONTAINER_NAME}\" \
    bash -c \"service ssh restart\" ${SILENT_HOOK}" || \
    exit_failure "failed to start SSH service"
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

if [[ $# -eq 0 ]]; then
    show_help_and_exit "${EXIT_SUCCESS}"
fi

while getopts "n:i:d:m:p:fvxh" opt; do
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
        exit_success "container is already exists: ${CONTAINER_NAME}"
    fi
fi

pull_sonic_mgmt_docker_image
start_local_container
show_local_container_login

exit_success "sonic-mgmt wan container is done!"
