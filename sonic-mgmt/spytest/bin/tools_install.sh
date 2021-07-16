#!/bin/bash

set -x

cat << EOF
    The following files are expected to be present in /project/scid/install
    ActiveTcl-8.5.19.8519-x86_64-linux-glibc-2.5-403583.tar.gz
    ActivePython-2.7.14.2717-linux-x86_64-glibc-2.12-404899.tar.gz
    ActivePython-3.6.6.3606-linux-x86_64-glibc-2.12.tar.gz
    ActivePython-3.7.1.0000-linux-x86_64-glibc-2.12-b2ae37a5.tar.gz
EOF

dir=$(dirname $0)
dir=$(cd $dir;pwd -P)
scid=$(cd $dir/..;pwd -P)

# source environment
. $dir/env

if [ -f $dir/.tools_env ]; then
  . $dir/.tools_env
fi

mkdir -p $SCID/install $SCID/tgen/ixia $SCID/tgen/stc
pushd $SCID/install

untar()
{
  file=$1
  if [ ! -f $file ]; then
    echo "$file not exists"
    if [ -f $dir/.tools_env ]; then
        bfile=$(basename $file)
        if [ -n "$PKG_URL" ]; then
            wget -O /tmp/$bfile $PKG_URL/$file /tmp/$bfile
        elif [ -n "$PKG_SERVER" ]; then
            sshpass -p $PKG_PASS scp -o StrictHostKeyChecking=no $PKG_USER@$PKG_SERVER:$PKG_ROOT/$file /tmp/$bfile
        fi
        if [ -f /tmp/$bfile ]; then
            mv /tmp/$bfile $file
        fi
    else
        exit 1
    fi
  fi
  tar -zxf $file
}

install_tcl64_85()
{
  pushd $SCID/install
    INSTALL=$SCID/tools/ActivTcl/8.5.19; rm -rf $INSTALL
    untar ActiveTcl-8.5.19.8519-x86_64-linux-glibc-2.5-403583.tar.gz
    pushd ActiveTcl-8.5.19.8519-x86_64-linux-glibc-2.5-403583
      export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./payload/lib
      ./payload/bin/tclsh8.5 install.tcl --directory $INSTALL
      pushd $SCID/tools/ActivTcl
        [ -f current ] || ln -s 8.5.19 current
      popd
    popd
    rm -rf ActiveTcl-8.5.19.8519-x86_64-linux-glibc-2.5-403583
  popd
}

install_python2()
{
  pushd $SCID/install
    INSTALL=$SCID/tools/ActivPython/2.7.14; rm -rf $INSTALL
    untar ActivePython-2.7.14.2717-linux-x86_64-glibc-2.12-404899.tar.gz
    if [ -d ActivePython-2.7.14.2717-linux-x86_64-glibc-2.12-404899 ]; then
      pushd ActivePython-2.7.14.2717-linux-x86_64-glibc-2.12-404899
        ./install.sh -v -I $INSTALL
        pushd $SCID/tools/ActivPython
          [ -f 2.7.14/bin/python ] || ln -s python3 2.7.14/bin/python
          [ -f current ] || ln -s 2.7.14 current
          cp -rf $SCID/tools/ActivTcl/current/lib/tclx8.4/ 2.7.14/lib/
        popd
      popd
      rm -rf ActivePython-2.7.14.2717-linux-x86_64-glibc-2.12-404899
      $dir/upgrade_requirements.sh
    fi
  popd
}

reinstall_python2()
{
  src="2.7.14"
  pushd $SCID/tools/ActivPython
    dst=$(readlink current)
    rm -rf $src.old
    mv $src $src.old
    if [ "$dst" = "$src" ]; then
      rm current; ln -s $src.old current
    fi
  popd
  install_python2
  pushd $SCID/tools/ActivPython
    if [ "$dst" = "$src" ]; then
      rm current;ln -s $src current
    fi
    rm -rf $src.old
  popd
  $dir/upgrade_requirements.sh
}

install_python366()
{
  pushd $SCID/install
    INSTALL=$SCID/tools/ActivPython/3.6.6; rm -rf $INSTALL
    untar ActivePython-3.6.6.3606-linux-x86_64-glibc-2.12.tar.gz
    pushd ActivePython-3.6.6.3606-linux-x86_64-glibc-2.12-*
      ./install.sh -v -I $INSTALL
      pushd $SCID/tools/ActivPython
        [ -f 3.6.6/bin/python ] || ln -s python3 3.6.6/bin/python
        cp -rf $SCID/tools/ActivTcl/current/lib/tclx8.4/ 3.6.6/lib/
      popd
    popd
    rm -rf ActivePython-3.6.6.3606-linux-x86_64-glibc-2.12-*
    export SPYTEST_PYTHON_VERSION=3.6.6
    $dir/upgrade_requirements.sh
  popd
}

install_python371()
{
  pushd $SCID/install
    INSTALL=$SCID/tools/ActivPython/3.7.1; rm -rf $INSTALL
    untar ActivePython-3.7.1.0000-linux-x86_64-glibc-2.12-b2ae37a5.tar.gz
    pushd ActivePython-3.7.1.0000-linux-x86_64-glibc-2.12-*
      ./install.sh -v -I $INSTALL
      pushd $SCID/tools/ActivPython
        [ -f 3.7.1/bin/python ] || ln -s python3 3.7.1/bin/python
        cp -rf $SCID/tools/ActivTcl/current/lib/tclx8.4/ 3.7.1/lib/
      popd
    popd
    rm -rf ActivePython-3.7.1.0000-linux-x86_64-glibc-2.12-*
    export SPYTEST_PYTHON_VERSION=3.7.1
    $dir/upgrade_requirements.sh
  popd
}

install_python3()
{
  install_python366
  #install_python371
}

reinstall_python3xx()
{
  src=$1
  pushd $SCID/tools/ActivPython
    dst=$(readlink current)
    rm -rf $src.old
    mv $src $src.old
    if [ "$dst" = "$src" ]; then
      rm current; ln -s $src.old current
    fi
  popd
  [ src = "3.6.6" ] && install_python366
  [ src = "3.7.1" ] && install_python371
  pushd $SCID/tools/ActivPython
    if [ "$dst" = "$src" ]; then
      rm current;ln -s $src current
    fi
    rm -rf $src.old
  popd
}

reinstall_python3()
{
  reinstall_python3xx "3.6.6"
  #reinstall_python3xx "3.7.1"
}

install_ixia_842()
{
  mkdir -p $SCID/tgen/ixia/
  pushd $SCID/tgen/ixia/
    rm -f 8.42
    untar IXIA_8.42EA.tar.gz
    ln -s IXIA_8.42EA 8.42
  popd
}

install_ixia_all()
{
  mkdir -p $SCID/tgen/ixia/
  pushd $SCID/tgen/ixia/
    rm -f all
    untar all_ixia.tar.gz
  popd
}

install_stc_491()
{
  mkdir -p $SCID/tgen/stc/
  pushd $SCID/tgen/stc/
    untar Spirent_TestCenter_4.91.tar.gz
    ln -s Spirent_TestCenter_4.91 4.91
  popd
}

install_tcl64_85
install_python2
install_python3

if [ -f $dir/.tools_env ]; then
  #install_ixia_842
  install_ixia_all
  #install_stc_491
fi

#reinstall_python3
#reinstall_python2

