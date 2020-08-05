#! /bin/bash

function show_help_and_exit() {
    echo "Usage $0 [options]"
    echo "Options with (*) are required"
    echo "-h -?                 : get this help"
    echo "-n <container name>   : (*) set the name of the Docker container"
    echo "-i <image ID>         : (*) specify Docker image to use"
    echo "-d <directory>        : specify directory inside container to bind mount to sonic-mgmt root (default \"/var/src/\")"
    exit $1
}

function start_and_config_container() {
    echo "Creating container"
    CURRENT_DIR=`pwd`/..
    docker run --name $CONTAINER_NAME -v $CURRENT_DIR:$LINK_DIR -d -t $IMAGE_ID bash > /dev/null

    if [[ "$?" != 0 ]]; then
        echo "Container creation failed, exiting"
        exit 1
    fi

    echo "Creating user $USER, group $USER, and setting UID and GID"
    docker exec $CONTAINER_NAME id $USER > /dev/null 2> /dev/null
    RET=`docker exec $CONTAINER_NAME echo $?`
    if [[ "$RET" != 0 ]]; then
        docker exec $CONTAINER_NAME sudo useradd $USER
    fi

    docker exec $CONTAINER_NAME grep -q "^$USER" /etc/group
    RET=`docker exec $CONTAINER_NAME echo $?`
    if [[ "$RET" != 0 ]]; then
        docker exec $CONTAINER_NAME sudo groupadd $USER
    fi

    HOST_GROUP_ID=`id $USER | grep -o "gid=[0-9]*" | cut -d "=" -f 2`
    HOST_USER_ID=`id $USER | grep -o "uid=[0-9]*" | cut -d "=" -f 2`

    docker exec $CONTAINER_NAME sudo usermod -u $HOST_USER_ID $USER
    docker exec $CONTAINER_NAME sudo groupmod -g $HOST_GROUP_ID $USER

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

    echo "Granting passwordless sudo privileges to $USER"
    docker exec $CONTAINER_NAME sudo usermod -aG sudo $USER
    # Be VERY careful modifying this line or you will break sudo functionality in your container
    docker exec $CONTAINER_NAME sudo sed -i "$ a $USER ALL=(ALL) NOPASSWD:ALL" /etc/sudoers

    echo "Creating home directory for $USER"
    docker exec $CONTAINER_NAME sudo mkdir -p /home/$USER
    docker exec $CONTAINER_NAME sudo chown -R $USER /home/$USER
}


function validate_parameters() {
    if [[ -z ${CONTAINER_NAME} ]]; then
        echo "Container name not set"
        show_help_and_exit 1
    fi

    if [[ -z ${IMAGE_ID} ]]; then
        echo "Image ID not set"
        show_help_and_exit 1
    fi

    if [[ -z ${LINK_DIR} ]]; then
        LINK_DIR="/var/src"
        echo "Using default bind mount directory $LINK_DIR"
    fi

    if [[ ! `id -Gn $USER | grep '\bdocker\b'` ]]; then
        echo "User $USER is not in the docker group"
        echo "Please add $USER to the docker group before proceeding"
        exit 1
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
    esac
done

validate_parameters
start_and_config_container
echo "Done!"
