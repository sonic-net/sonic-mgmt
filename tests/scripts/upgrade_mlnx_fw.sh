#!/bin/bash -e

EXIT_FS_MOUNT_MOUNT_FAILED=111
EXIT_FS_MOUNT_UNMOUNT_FAILED=112
EXIT_MLNX_QUERY_FAILED=113
EXIT_NO_FW_INFO=114
EXIT_MLNX_FW_UPGRADE_FAILED=115

upgradeMLNXFW() {
    FS_PATH="/host/image-${TARGET_FW#SONiC-OS-}/fs.squashfs"
    FS_MOUNTPOINT="/tmp/image-${TARGET_FW#SONiC-OS-}-fs"

    mkdir -p "${FS_MOUNTPOINT}"
    mount -t squashfs "${FS_PATH}" "${FS_MOUNTPOINT}" || exit ${EXIT_FS_MOUNT_FAILED}

    FW_FILE="${FS_MOUNTPOINT}/etc/mlnx/fw-SPC.mfa"
    FW_QUERY="/tmp/mlnxfwmanager-query.txt"

    mlxfwmanager --query -i "${FW_FILE}" > "${FW_QUERY}" || exit ${EXIT_MLNX_QUERY_FAILED}

    FW_INFO="$(grep FW ${FW_QUERY})"
    FW_CURRENT="$(echo ${FW_INFO} | cut -f2 -d' ')"
    FW_AVAILABLE="$(echo ${FW_INFO} | cut -f3 -d' ')"

    [ -z "${FW_CURRENT}" -o -z "${FW_AVAILABLE}" ] && exit ${EXIT_NO_FW_INFO}

    if [ "${FW_CURRENT}" == "${FW_AVAILABLE}" ]; then
        echo "Mellanox firmware is up to date"
    else
        echo "Mellanox firmware upgrade is required. Installing compatible version..."
        mlxfwmanager -i "${FW_FILE}" -u -f -y || exit ${EXIT_MLNX_FW_UPGRADE_FAILED}
    fi

    umount -rf "${FS_MOUNTPOINT}" || exit ${EXIT_FS_UNMOUNT_FAILED}
    rm -rf "${FS_MOUNTPOINT}"
}

TARGET_FW=$(sonic_installer list | grep "Next: " | cut -d ' ' -f 2)

upgradeMLNXFW
