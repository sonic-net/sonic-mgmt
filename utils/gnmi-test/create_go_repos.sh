#!/bin/bash
echo $GOROOT
echo $GOPATH
echo $GOBIN
go_bin=${GOROOT}/bin/go

clone_version() {
  echo "Working on: " $1 $2
  ${go_bin} get -v -d $1
  cd ${GOPATH}/src/$1
  git checkout -b gopath $2
}

mkdir -p ${GOPATH}
mkdir -p ${GOPATH}/src
mkdir -p ${GOPATH}/bin
mkdir -p ${GOPATH}/pkg

# download and install
clone_version google.golang.org/grpc v1.27.0
#clone_version google.golang.org/genproto bd9b4fb
clone_version github.com/golang/protobuf \
  d04d7b157bb510b1e0c10132224b616ac0e26b17
#  8d0c54c1246661d9a51ca0ba455d22116d485eaa
# make install to install protoc-gen-go and libs
go install ${GOPATH}/src/github.com/golang/protobuf/protoc-gen-go

clone_version github.com/openconfig/gnmi \
  e7106f7f5493a9fa152d28ab314f2cc734244ed8

clone_version github.com/golang/glog \
  23def4e6c14b4da8ac2ed8007337bc5eb5007998 

clone_version github.com/cenkalti/backoff

clone_version github.com/openconfig/ygot \
	6daf745bd5f14eda714e98cec83884e5b3954898

clone_version github.com/google/go-cmp \
  f6dc95b586bc4e5c03cc308129693d9df2819e1c

clone_version github.com/kylelemons/godebug/pretty \
 fa7b53cdfc9105c70f134574002f406232921437

clone_version github.com/openconfig/goyang/pkg/yang \
 a00bece872fc729c37e32bc697c8f3e7eb019172

clone_version github.com/pmezard/go-difflib/difflib \
 5d4384ee4fb2527b0a1256a821ebfc92f91efefc

clone_version golang.org/x/xerrors \
9bdfabe68543c54f90421aeb9a60ef8061b5b544

clone_version github.com/googleapis/googleapis \
 c08dcec05ce1c181bcdbce59cabba36e0e541ff6
