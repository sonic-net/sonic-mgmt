#!/bin/bash
# hft.sh supplies the platform-specific create options, but cannot take a Docker CMD.
# Intercept just its docker create in this shell; let hft.service start it normally.
owner_label=$1
shift
cmd=("$@")
exec {result_fd}>&1 1>&2
docker() {
    case "$1:$2" in
        inspect:--type) return 1 ;;  # A simultaneous create will fail on the container name.
        create:*)
            [[ " $* " == *' --name=hft '* && ${!#} == docker-hft:latest ]] || exit 1
            command docker create --label "$owner_label" "${@:2}" "${cmd[@]}" >&"$result_fd"
            exit $?
            ;;
        *) echo "Unexpected docker operation in hft.sh: $1" >&2; exit 1 ;;
    esac
}
source /usr/bin/hft.sh start
exit 1
