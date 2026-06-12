#!/bin/bash
#
# Background EEPROM reader for the CMIS CDB background mode stress test.
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
#                                   <pgid_file> <read_eeprom_cmd> [read_interval]
#
# Loops running "<read_eeprom_cmd> -p <port> -n 0 -o 0 -s 1", counting total
# attempts and failures, and flushes the running counts to <total_file> /
# <fail_file> on TERM/INT/EXIT. <read_eeprom_cmd> is passed in (not hardcoded)
# so the command spelling stays single-sourced from
# cli_helpers.SFPUTIL_READ_EEPROM on the Python side.
#
# [read_interval] (optional, default 0) is the delay in seconds between reads
# (fractional allowed). 0 runs the loop at maximum rate -- the intended I2C bus
# contention for the stress test; a non-zero value throttles the load rate.
set -u

port="$1"
fail_file="$2"
total_file="$3"
pgid_file="$4"
read_eeprom_cmd="$5"
# Optional inter-read delay in seconds (fractional ok). Default 0 = max rate.
read_interval="${6:-0}"

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
# normal EXIT) so the Python side can read accurate totals.  Note bash defers a
# trap until the in-flight foreground command (sfputil) returns, and a SIGKILL
# bypasses the trap entirely -- so the per-iteration write_counts below, not
# this trap, is what makes the totals durable across an abrupt kill.
trap 'write_counts; exit 0' TERM INT EXIT

# Publish an initial 0/0 so the counter files always exist for join() to read,
# even if the reader is killed before the first iteration completes.
write_counts

while true; do
    total_count=$((total_count + 1))
    # read_eeprom_cmd is intentionally left unquoted so a multi-word command
    # ("sfputil read-eeprom") word-splits into separate argv entries.
    if ! $read_eeprom_cmd -p "$port" -n 0 -o 0 -s 1 >/dev/null 2>&1; then
        fail_count=$((fail_count + 1))
    fi
    # Flush counts every iteration so a SIGKILL (which bypasses the trap) or a
    # trap deferred behind a stuck sfputil loses at most the in-flight update,
    # not the whole running total.  Each iteration already forks sfputil (tens
    # of ms), so two tiny tmpfs writes are negligible.
    write_counts
    # Optional rate control. Skip the sleep fork entirely at the default rate 0
    # so the max-rate stress keeps its current behavior.
    if [ "$read_interval" != "0" ]; then
        sleep "$read_interval"
    fi
done
