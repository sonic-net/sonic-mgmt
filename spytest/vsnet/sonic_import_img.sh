#!/bin/bash

. $(dirname $0)/env

IMG=$1;shift

DUT_PREFIX=${DUT_PREFIX:=V}
DCOUNT=${DCOUNT:=2}
IMG_NAME=${IMG_NAME:=squashfs}
VOL_NAME=${VOL_NAME:=squashfs}
MEM=${MEM:=6}
CPU=${CPU:=3}
TEMP=$(mktemp -d)
ROOT=${ROOT:=/data}
if [ "$PARENT" = "" ]; then
  PARENT=$TEMP
  PARENT=$ROOT/work
fi
if [ -z "$IMG" ]; then
  IMG=$ROOT/images/sonic-vs.img
fi
CIMGMNT=$PARENT/extracted
CIMGMNT=$PARENT/extracted
CROOTFS=$PARENT/squashfs

trap "rm -rf $TEMP" EXIT

mkdir -p $PARENT

extract_image()
{
  img=$1;dir=$2;mnt=$dir.1
  rm -rf $dir $mnt; mkdir $dir $mnt
  qemu-nbd --disconnect /dev/nbd0
  if ! qemu-nbd --connect=/dev/nbd0 $img; then
    echo "Failed to read image $img"
    exit 1
  fi
  mount -o loop,ro,norecovery,offset=$((512*$(fdisk /dev/nbd0 -l -o Start | tail -1))) /dev/nbd0 $mnt
  rsync -aqPHSX --numeric-ids $mnt/ $dir
  umount $mnt
  qemu-nbd --disconnect /dev/nbd0
  rm -rf $mnt
}

create_firstboot()
{
cat << EOF > $1
  echo VSNet Firstboot
  chmod 0777 /tmp
EOF
}

create_cron_script()
{
for((i=0;i<5;i++)); do
  ifconfig
  DOCKER0_IP=$(ifdata -pa docker0)
  [ -n "$DOCKER0_IP" ] && break
  sleep 5
done
cat << EOF > $1/bin/vsnet.sh
#!/bin/sh

if [ -n "$DOCKER0_IP" ]; then
  cmd="ip route add default via $DOCKER0_IP"
  echo \$cmd >> /var/log/vsnet.log
  \$cmd
  docker exec mgmt-framework chmod 0777 /tmp >> /var/log/vsnet.log
fi

EOF
chmod +x $1/bin/vsnet.sh
}

remove_image_data()
{
  rm -rf $CIMGMNT
}

prepare_image_data()
{
  if [ ! -d $CIMGMNT ]; then
    if [ ! -f "$IMG" ]; then
      echo "Invalid image path '$IMG'"
      exit 1
    fi
    extract_image $IMG $CIMGMNT
  fi

  #build_version=$(grep build_version $CIMGMNT/image-*/sonic_version.yml | cut -d \' -f2)
  #build_image="image-$build_versio"
  build_image=$(basename `ls -d $CIMGMNT/image-*`)

  if [ ! -d $CROOTFS ]; then
    unsquashfs -n -f -d $CROOTFS $CIMGMNT/$build_image/fs.squashfs
    sed -i "/127.0.0.1\s*localhost/a 127.0.0.1 sonic" $CROOTFS/etc/hosts
  fi
  if [ ! -f $CROOTFS/host/machine.conf ]; then
    mkdir -p $CROOTFS/host
    cp $CIMGMNT/machine.conf $CROOTFS/host/
  fi
  if [ ! -f $CROOTFS/host/ztp/ztp_cfg.json ]; then
    mkdir -p $CROOTFS/host/ztp
    echo '{"admin-mode" : false}' > $CROOTFS/host/ztp/ztp_cfg.json
  fi
  if [ ! -d $CROOTFS/host/$build_image/platform ]; then
    mkdir -p $CROOTFS/host/$build_image/platform
    touch $CROOTFS/host/$build_image/platform/firsttime
    #cp -rf $CIMGMNT/$build_image/rw $CROOTFS/host/$build_image/
  fi
  create_firstboot $CROOTFS/host/$build_image/first_boot.sh
  chmod 0777 $CROOTFS/tmp
  rm -f $CROOTFS/usr/lib/tmpfiles.d/systemd-nologin.conf
  create_cron_script $CROOTFS
}

create_docker_image()
{
  # recreate the image
  docker images -q $IMG_NAME | xargs -r -L 1 docker rmi -f
  tar -C $CROOTFS -c . | docker import - $IMG_NAME

  # recreate the volume
  docker volume ls -q --filter "name=^$VOL_NAME$" | xargs -r -L 1 docker volume rm -f
  docker volume create $VOL_NAME

  # copy sonic docker file system into volume
  #docker run --rm -v /$CIMGMNT/$build_image/docker/:/src -v $VOL_NAME:/var/lib/docker -w /var/lib/docker eeacms/rsync rsync -aqPHSX --numeric-ids /src/ .
  cp -rf $CIMGMNT/$build_image/docker/* /var/lib/docker/volumes/$VOL_NAME/_data

  CON_NAME=${CON_NAME:=squashfs}
  echo docker rm -f $CON_NAME
  #docker run -it --rm --privileged -h $CON_NAME --add-host sonic:127.0.0.1 --name $CON_NAME -v $VOL_NAME:/var/lib/docker $IMG_NAME /sbin/init
  echo docker run -itd --rm --privileged -h $CON_NAME --add-host sonic:127.0.0.1 --name $CON_NAME -v $VOL_NAME:/var/lib/docker $IMG_NAME /sbin/init
}

create_devices()
{
  for ((i=1;i<=$DCOUNT;i++)); do
    DUT=$DUT_PREFIX$i;CPORT=$((CPORT+1))
    docker ps -aq --filter "name=^$DUT$" | xargs -r -L 1 docker rm -f
    docker volume ls -q --filter "name=^$DUT$" | xargs -r -L 1 docker volume rm -f
    rm -rf /var/lib/docker/volumes/$DUT
    cp -rf /var/lib/docker/volumes/$VOL_NAME /var/lib/docker/volumes/$DUT
    OPTS="--privileged --name $DUT"
    OPTS="$OPTS -h $DUT --add-host sonic:127.0.0.1"
    #OPTS="$OPTS --rm"
    OPTS="$OPTS --restart=always"
    OPTS="$OPTS -v $DUT:/var/lib/docker"
    OPTS="$OPTS -v /var/log/$DUT:/var/log"; mkdir -p /var/log/$DUT/save
    #OPTS="$OPTS -v /var/tmp/$DUT:/tmp"; mkdir -p /var/tmp/$DUT
    #OPTS="$OPTS --tmpfs /tmp --tmpfs /run"
    #OPTS="$OPTS --mount type=tmpfs,destination=/tmp,tmpfs-mode=0777 "
    #OPTS="$OPTS --network host"
    OPTS="$OPTS --memory=${MEM}g"
    OPTS="$OPTS --cpus=${CPU}"
    pkill -F /tmp/$DUT.pid 2>/dev/null; rm -f /tmp/$DUT.pid; rm -rf /dev/ttyV$i
    daemonize -p /tmp/$DUT.pid /usr/bin/socat -d -d pty,raw,echo=0,link=/dev/ttyV$i tcp4-listen:$CPORT,reuseaddr,fork
    OPTS="$OPTS -v /dev/ttyV$i:/dev/tty1"
    docker run -itd $OPTS $IMG_NAME /sbin/init
  done
}

increase_sysctl_value()
{
  val=$(sysctl -n $1)
  if [ $val -lt $2 ]; then
    sysctl $1=$2
  fi
}

increase_system_limits()
{
  increase_sysctl_value "fs.inotify.max_user_instances" 512
}

increase_system_limits
remove_image_data
prepare_image_data
create_docker_image
create_devices

exit 0
