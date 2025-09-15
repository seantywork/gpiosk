#!/bin/bash

if [ ! "$EUID" -ne 0 ]
then 
    echo "do not run as root"
    exit 1
fi


if [ -d  xdp-tools ]
then
  echo "xdp-tools already exists"
  exit 1
fi

git clone https://github.com/xdp-project/xdp-tools

sudo apt update 

sudo apt install -y clang llvm libelf-dev libpcap-dev build-essential libc6-dev-armel-cross m4


sudo apt install -y linux-headers-$(uname -r)

pushd xdp-tools

./configure

popd

pushd xdp-tools

make

sudo make install 

popd 


pushd xdp-tools/lib/libbpf/src 

sudo make install 

popd 

sudo ln -s /usr/include/aarch64-linux-gnu/asm /usr/include/asm
sudo ln -s /usr/include/aarch64-linux-gnu/bits /usr/include/bits
sudo ln -s /usr/include/aarch64-linux-gnu/sys /usr/include/sys
sudo ln -s /usr/include/aarch64-linux-gnu/gnu /usr/include/gnu