#!/bin/bash

mkdir -p /tmp/$USER
exec &> >(tee /tmp/$USER/tools_install.log)

#export SCID=/tmp/projects/scid

cat << EOF
    The following files are expected to be present in /project/scid/install
    ActiveTcl-8.5.19.8519-x86_64-linux-glibc-2.5-403583.tar.gz
    ActivePython-2.7.14.2717-linux-x86_64-glibc-2.12-404899.tar.gz
    all_ixia.tar.gz
    all_stc.tar.gz
EOF

dir=$(dirname $0)
dir=$(cd $dir;pwd -P)
scid=$(cd $dir/..;pwd -P)

# sourde environment
. $dir/env

if [ -f $dir/.tools_env ]; then
  . $dir/.tools_env
fi

mkdir -p $SCID/install $SCID/tgen/ixia $SCID/tgen/stc
pushd $SCID/install

untar()
{
  here=$PWD
  file=$1;shift
  in=$1
  if [ ! -f $file ]; then
    echo "$file not exists"
    if [ -f $dir/.tools_env ]; then
        bfile=$(basename $file)
        if [ -n "$PKG_URL" ]; then
            wget -inet4-only -O /tmp/$bfile $PKG_URL/$file /tmp/$bfile
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
  [ -n "$in" ] && pushd $in
  tar -zxf $here/$file
  [ -n "$in" ] && popd
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
      export SCID_PYTHON_BIN=""
      export SPYTEST_PYTHON_VERSION=2.7.14
      $dir/upgrade_requirements.sh
    fi
  popd
}

install_python3()
{
  pushd $SCID/install
    INSTALL=$SCID/tools/ActivPython/3.8.8; rm -rf $INSTALL
    untar ActivePython-3.8.8.0000-linux-x86_64-glibc-2.17-5222f37a.tar.gz
    pushd ActivePython-3.8.8.0000-linux-x86_64-glibc-2.17-*
      ./install.sh -v -I $INSTALL
      pushd $SCID/tools/ActivPython
        [ -f 3.8.8/bin/python ] || ln -s python3 3.8.8/bin/python
        cp -rf $SCID/tools/ActivTcl/current/lib/tclx8.4/ 3.8.8/lib/
      popd
    popd
    rm -rf ActivePython-3.8.8.3606-linux-x86_64-glibc-2.12-*
    export SCID_PYTHON_BIN=""
    export SPYTEST_PYTHON_VERSION=3.8.8
    $dir/upgrade_requirements.sh
  popd
}

install_ixia_all()
{
  pushd $SCID/install
    rm -rf $SCID/tgen/ixia/all
    untar all_ixia.tar.gz $SCID/tgen/ixia
  popd
}

install_stc_all()
{
  pushd $SCID/install
    rm -rf $SCID/tgen/stc
    mkdir $SCID/tgen/stc
    untar all_stc.tar.gz $SCID/tgen/stc
  popd
}

install_tcl64_85
install_python2
#install_python3

if [ -f $dir/.tools_env ]; then
  install_ixia_all
  install_stc_all
fi
