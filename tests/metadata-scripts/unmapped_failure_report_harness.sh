#!/bin/bash
set -eu

# All firmware writes go into a disposable root. Namespace teardown releases
# the bind mounts, including on failure; no DUT service or Redis is touched.
exec unshare --mount --net --pid --fork /bin/bash -seu -- "$1" "$2" <<'SANDBOX'
test_dir=$1
event_guid=$2
root="$test_dir/root"
mount --make-rprivate /
mkdir -p "$root"/{host,tmp,dev,proc,test,usr/local/bin,usr/local/lib} "$test_dir/bin"
mount -t proc -o ro,nosuid,nodev,noexec proc "$root/proc"

# Use the DUT's actual shell, Python and libraries, read-only.
for path in /usr /bin /lib /lib64; do
    if [[ -d "$path" ]]; then
        mkdir -p "$root$path"
        mount --bind "$path" "$root$path"
        mount -o remount,bind,ro "$root$path"
    fi
done
mkdir -p "$test_dir/local-bin" "$test_dir/local-lib"
mount --bind "$test_dir/local-bin" "$root/usr/local/bin"
mount --bind "$test_dir/local-lib" "$root/usr/local/lib"
touch "$root/dev/null"
mount --bind /dev/null "$root/dev/null"

# Limit command lookup to the startup/reporting dependencies. No installer,
# reboot, config or service-changing command is available in this PATH.
for cmd in dirname cp chmod mkdir rm getopt awk du df grep sed cat tr cut tail; do
    ln -s "$(readlink -f "$(command -v "$cmd")")" "$test_dir/bin/$cmd"
done
ln -s /usr/bin/python3 "$test_dir/bin/python"
cat > "$test_dir/bin/sonic_installer" <<'INSTALLER'
#!/bin/bash
[[ "$*" == "list" ]] || exit 97
printf 'Current: SONiC-OS-20251110.40\n'
INSTALLER
printf '#!/bin/bash\nexit 1\n' > "$test_dir/bin/redis-cli"
# There is no syslog socket in the isolated root.
printf '#!/bin/bash\nexit 0\n' > "$test_dir/bin/logger"
chmod +x "$test_dir/bin/"{sonic_installer,redis-cli,logger}

cat > "$root/host/machine.conf" <<'MACHINE'
onie_machine=kvm
onie_platform=x86_64-kvm_x86_64-r0
onie_switch_asic=vs
MACHINE
printf 'image_version="20251110.41"\n' > "$root/tmp/probe-firmware.bin"
mount --bind "$test_dir" "$root/test"
mount -o remount,bind,ro "$root/test"

# Execute the unmodified script. Its own ERR/EXIT traps produce the report.
exec chroot "$root" /usr/bin/env -i PATH=/test/bin HOME=/tmp \
    /bin/bash -e /test/update_firmware -e "$event_guid" probe-firmware.bin
SANDBOX
