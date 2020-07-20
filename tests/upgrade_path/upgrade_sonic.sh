#!/bin/bash

DOWNLOADED_IMAGE_VERSION="Unknown"

function get_host_free_size()
{
    free_size=`df -BM --output=avail /host | grep -oE "[0-9]*"`
    if [ -z ${free_size} ]
    then
        exit 1
    fi
    echo ${free_size}
}

function do_install()
{
    install_url=$1
    sonic_installer install ${install_url} -y >/tmp/sonic_installer.stdout 2>&1
    return $?
}

function prepare_tmpfs()
{
    image_url=$1
    #create tmpfs
    mkdir -p /tmp/tmpfs 2>/dev/null
    umount /tmp/tmpfs 2>/dev/null
    #mount tmpfs
    mount -t tmpfs -o size=1300M tmpfs /tmp/tmpfs
    #prepare sonic image
    download_image ${image_url} /tmp/tmpfs/sonic-image
}

function cleanup()
{
    sync
    if [ -d '/tmp/tmpfs' ]
    then
        umount /tmp/tmpfs 2>/dev/null
        rm -rf /tmp/tmpfs 2>/dev/null
    fi
    # If sonic device is configured with minigraph, remove config_db.json
    # to force next image to load minigraph.
    if [ -f '/host/old_config/minigraph.xml' ]
    then
        rm -f /host/old_config/config_db.json
    fi
}

function install_sonic()
{
    image_url=$1
    free_disk_size=`get_host_free_size`
    DISK_THRESHOLD=2000
    if [ ${free_disk_size} -ge ${DISK_THRESHOLD} ]
    then
        local download_path="/tmp/downloaded_sonic_image"
        download_image ${image_url} ${download_path}
        do_install ${download_path}
        ret=$?
        rm -f ${download_path}
    else
        prepare_tmpfs ${image_url}
        do_install /tmp/tmpfs/sonic-image
        ret=$?
    fi
    cleanup
    return ${ret}
}

function download_image()
{
    image_url=$1
    save_to=$2
    rm -f ${save_to} 2>/dev/null
    curl -o ${save_to} -s ${image_url}
    if [ $? -ne 0 ]
    then
        echo "Failed to download from ${image_url}"
        exit $?
    fi
    DOWNLOADED_IMAGE_VERSION=`sudo sonic_installer binary_version ${save_to}`
}

function usage()
{
    echo "USEAGE: $0 image_url"
}

if [ $# -ne 1 ]
then
    usage
    exit 1
fi

install_sonic $1
ret=$?
if [ ${ret} -eq 0 ]
then
    echo "installed_version ${DOWNLOADED_IMAGE_VERSION}"
fi

exit ${ret}

