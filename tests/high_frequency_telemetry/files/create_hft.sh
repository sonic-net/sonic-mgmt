#!/bin/bash
# hft.sh supplies the platform-specific create options, but cannot take a Docker CMD.
# Intercept just its docker create in this shell; let hft.service start it normally.
cmd=("$@")
docker() {
    case "$1:$2" in
        inspect:--type) return 1 ;;  # The fixture removed the old hft container.
        create:*)
            [[ " $* " == *' --name=hft '* && ${!#} == docker-hft:latest ]] || exit 1
            command docker "$@" "${cmd[@]}"
            exit $?
            ;;
        *) echo "Unexpected docker operation in hft.sh: $1" >&2; exit 1 ;;
    esac
}
# /usr/local/bin/hft.sh is the systemd wrapper; it calls this generated Docker launcher.
source /usr/bin/hft.sh start
exit 1
