#! /bin/bash

function setup_local_image() {
    tmpdir=`mktemp -d`

    AKEY_FILE=$HOME/.ssh/authorized_keys
    PRIVKEY_FILE=$HOME/.ssh/id_rsa_docker_sonic_mgmt
    PUBKEY_FILE=$HOME/.ssh/id_rsa_docker_sonic_mgmt.pub

    [ -f $PRIVKEY_FILE ] || ssh-keygen -t rsa -q -N "" -f $PRIVKEY_FILE

    if [ -f $AKEY_FILE ]; then
        PUBKEY=`cat $PUBKEY_FILE`
        grep -q "$PUBKEY" $AKEY_FILE || cat $PUBKEY_FILE >> $AKEY_FILE
    else
        cat $PUBKEY_FILE > $AKEY_FILE
    fi

    cp $PRIVKEY_FILE $tmpdir/id_rsa

    chmod 600 $tmpdir/id_rsa

    cat <<EOF > $tmpdir/Dockerfile.j2
FROM {{ IMAGE_ID }}

RUN sudo groupadd -g {{ GROUPID }} {{ GROUPNAME }}
RUN sudo useradd --shell /bin/bash -u {{ USERID }} -g {{ GROUPID }} -d /home/{{ USERNAME }} {{ USERNAME }}

RUN sudo sed -i "$ a {{ USERNAME }} ALL=(ALL) NOPASSWD:ALL" /etc/sudoers

RUN sudo usermod -aG sudo {{ USERNAME }}

USER {{ USERNAME }}

ADD --chown={{ USERNAME }} id_rsa /home/{{ USERNAME }}/.ssh/id_rsa

ENV HOME=/home/{{ USERNAME }}
ENV USER {{ USERNAME }}
WORKDIR $HOME

EOF

    cat <<EOF > $tmpdir/data.env
IMAGE_ID=$IMAGE_ID
GROUPID=$HOST_GROUP_ID
USERID=$HOST_USER_ID
GROUPNAME=$USER
USERNAME=$USER
EOF

    j2 -o $tmpdir/Dockerfile $tmpdir/Dockerfile.j2 $tmpdir/data.env

    echo "Build image $LOCAL_IMAGE_NAME from $tmpdir ..."

    docker build -t $LOCAL_IMAGE_NAME $tmpdir

    rm -rf $tmpdir
}

DOCKER_SONIC_MGMT="docker-sonic-mgmt"
DOCKER_REGISTRY="sonicdev-microsoft.azurecr.io:443"
LOCAL_IMAGE_NAME=docker-sonic-mgmt-`echo "$USER" | tr '[:upper:]' '[:lower:]'`

function show_help_and_exit() {
    echo "Usage $0 [options]"
    echo "Options with (*) are required"
    echo ""
    echo "-h -?                 : get this help"
    echo ""
    echo "-n <container name>   : (*) set the name of the Docker container"
    echo ""
    echo "-i <image ID>         : specify Docker image to use. This can be an image ID (hashed value) or an image name."
    echo "                      | If no value is provided, defaults to the following images in the specified order:"
    echo "                      |   1. The local image named \"docker-sonic-mgmt\""
    echo "                      |   2. The local image named \"sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt\""
    echo "                      |   3. The remote image at \"sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt\""
    echo ""
    echo "-d <directory>        : specify directory inside container to bind mount to sonic-mgmt root (default \"/var/src/\")"
    exit $1
}

function start_local_container() {
    echo "Creating container $CONTAINER_NAME"
    SCRIPT_DIR=`dirname $0`
    cd $SCRIPT_DIR
    PARENT_DIR=`pwd`/..
    docker run --name $CONTAINER_NAME -v $PARENT_DIR:$LINK_DIR -d -t $LOCAL_IMAGE_NAME bash > /dev/null

    if [[ "$?" != 0 ]]; then
        echo "Container creation failed, exiting"
        exit 1
    fi

    echo "Verifying UID and GID in container matches host"
    CONTAINER_USER_ID=`docker exec $CONTAINER_NAME sh -c "id $USER | grep -o \"uid=[0-9]*\" | cut -d \"=\" -f 2"`
    CONTAINER_GROUP_ID=`docker exec $CONTAINER_NAME sh -c "id $USER | grep -o \"gid=[0-9]*\" | cut -d \"=\" -f 2"`

    if [[ "$HOST_USER_ID" != "$CONTAINER_USER_ID" ]]; then
        echo "User ID mismatch between host and container"
        exit 1
    fi

    if [[ "$HOST_GROUP_ID" != "$CONTAINER_GROUP_ID" ]]; then
        echo "Group ID mismatch between host and container"
        exit 1
    fi
}


function pull_sonic_mgmt_docker_image() {
    if ! docker info > /dev/null 2> /dev/null; then
        echo "Unable to access Docker daemon"
        echo "Hint: make sure $USER is a member of the docker group"
        exit 1
    fi

    if [[ -z ${CONTAINER_NAME} ]]; then
        echo "Container name not set"
        show_help_and_exit 1
    fi

    if [[ -z ${IMAGE_ID} ]]; then
        if docker images --format "{{.Repository}}" | grep -q "^${DOCKER_SONIC_MGMT}$"; then
            IMAGE_ID=$DOCKER_SONIC_MGMT
        elif docker images --format "{{.Repository}}" | grep -q "^${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}$"; then
            IMAGE_ID=${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}
        elif echo "Pulling image from registry" && docker pull ${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}; then
            IMAGE_ID=${DOCKER_REGISTRY}/${DOCKER_SONIC_MGMT}
        else
            echo "Unable to find a usable default image, please specify one manually"
            show_help_and_exit 1

        fi
        echo "Using default image $IMAGE_ID"
    fi

    if [[ -z ${LINK_DIR} ]]; then
        LINK_DIR="/var/src"
        echo "Using default bind mount directory $LINK_DIR"
    fi
}

if [[ "$#" == 0 ]]; then
    show_help_and_exit 0
fi

while getopts "h?n:i:d:" opt; do
    case ${opt} in
        h|\? )
            show_help_and_exit 0
            ;;
        n )
            CONTAINER_NAME=${OPTARG}
            ;;
        i )
            IMAGE_ID=${OPTARG}
            ;;
        d )
            LINK_DIR=${OPTARG}
            ;;
        u )
            DOCKER_USER=${OPTARG}
            ;;
        p )
            DOCKER_PW=${OPTARG}
    esac
done

HOST_GROUP_ID=`id $USER | grep -o "gid=[0-9]*" | cut -d "=" -f 2`
HOST_USER_ID=`id $USER | grep -o "uid=[0-9]*" | cut -d "=" -f 2`

pull_sonic_mgmt_docker_image
setup_local_image
start_local_container
echo "Done!"
