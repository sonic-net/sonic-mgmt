
start() {
    docker create --privileged --net=host \
        --name=$DOCKERNAME docker-saiserver-brcm:latest || {
            echo "Failed to docker run" >&1
            exit 4
    }

    /usr/local/bin/container start ${DOCKERNAME}
}

wait() {
    /usr/local/bin/container wait $DOCKERNAME
}

stop() {
    /usr/local/bin/container stop $DOCKERNAME
}

DOCKERNAME=saiserver

# read SONiC immutable variables
[ -f /etc/sonic/sonic-environment ] && . /etc/sonic/sonic-environment

case "$1" in
    start|wait|stop)
        $1
        ;;
    *)
        echo "Usage: $0 {start namespace(optional)|wait namespace(optional)|stop namespace(optional)}"
        exit 1
        ;;
esac
