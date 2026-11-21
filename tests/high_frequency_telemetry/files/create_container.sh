#!/bin/bash
# The generated SONiC launcher owns the platform-specific create options but has
# no create-only/command-argument interface. Scope this adapter to this one shell:
# capture its docker create, add the transaction label and CMD, and exit before
# the launcher starts the service. Neither the installed launcher nor image changes.
service=$1 label=$2 launcher=$3
shift 3
container_args=("$@")
case "$service" in
    hft) image=docker-hft:latest ;;
    otel) image=docker-sonic-otel:latest ;;
    *) exit 1 ;;
esac
if [[ $(grep -Ec '^[[:space:]]*docker create[[:space:]]' "$launcher") != 1 ]]; then
    echo "Unsupported $service.sh launcher: expected one docker create command" >&2
    exit 1
fi
# An inherited fd (often 3) holds the DUT transaction flock. Allocate a free
# descriptor for the result instead of clobbering any of the caller's fds.
exec {result_fd}>&1 1>&2
docker() {
    case "$1:$2" in
        inspect:--type) return 1 ;; # Always take the create path; a name collision fails atomically.
        network:inspect) command docker "$@" ;;
        create:*)
            local named=false arg
            for arg in "$@"; do [[ $arg == --name="$service" ]] && named=true; done
            if [[ $named != true || ${!#} != "$image" ]]; then
                echo "Unsupported $service.sh docker create invocation" >&2
                exit 1
            fi
            command docker create --label "$label" "${@:2}" "${container_args[@]}" >&"$result_fd"
            exit $?
            ;;
        *) echo "Unexpected $service.sh docker operation: $1" >&2; exit 1 ;;
    esac
}
# shellcheck disable=SC1091
source "$launcher" start
exit 1
