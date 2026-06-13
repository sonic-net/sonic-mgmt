#!/bin/bash
#
# Background EEPROM reader for the CMIS CDB background-mode stress test (TC13).
#
# Launched under `setsid` by _RemoteBgReader.start() in
# tests/transceiver/eeprom/cmis/test_cdb_background_mode.py, so this shell is
# its own session / process-group leader (PGID == this shell's PID). The shell
# writes its own PID to the pgid file immediately; the Python side reads that to
# learn the PGID and later signals the whole group (`kill -- -<pgid>`) so any
# in-flight read-eeprom child dies with the loop instead of orphaning on the
# I2C bus.
#
# Usage:
#   setsid bash bg_eeprom_reader.sh <port> <fail_file> <total_file> \
#                                   <pgid_file> <read_eeprom_cmd>
#
# Loops running "<read_eeprom_cmd> -p <port> -n 0 -o 0 -s 1", counting total
# attempts and failures, and flushes the running counts to <total_file> /
# <fail_file> on TERM/INT/EXIT. <read_eeprom_cmd> is passed in (not hardcoded)
# so the command spelling stays single-sourced from
# cli_helpers.SFPUTIL_READ_EEPROM on the Python side.
set -u

port="$1"
fail_file="$2"
total_file="$3"
pgid_file="$4"
read_eeprom_cmd="$5"

# Record this shell's PID so the launcher can capture the PGID. setsid forks
# before exec, so the launcher's own $! would point at the setsid wrapper, not
# this shell -- hence we publish $$ here rather than relying on $!.
echo "$$" > "$pgid_file"

fail_count=0
total_count=0

write_counts() {
    echo "$fail_count" > "$fail_file"
    echo "$total_count" > "$total_file"
}

# Flush the final counts on any orderly stop (SIGTERM from join(), SIGINT, or
# normal EXIT) so the Python side can read accurate totals.
trap 'write_counts; exit 0' TERM INT EXIT

while true; do
    total_count=$((total_count + 1))
    # read_eeprom_cmd is intentionally left unquoted so a multi-word command
    # ("sfputil read-eeprom") word-splits into separate argv entries.
    if ! $read_eeprom_cmd -p "$port" -n 0 -o 0 -s 1 >/dev/null 2>&1; then
        fail_count=$((fail_count + 1))
    fi
done
