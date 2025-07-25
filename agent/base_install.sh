#!/bin/bash
sudo apt update
sudo apt install -y zip bison build-essential cmake flex git curl libedit-dev \
    libllvm12 llvm-10-dev libclang-10-dev python python3 python3-setuptools zlib1g-dev libelf-dev libfl-dev \
    bpfcc-tools linux-headers-$(uname -r) libelf-dev libpcap-dev gcc-multilib build-essential \
    liblzma-dev arping iperf3
sudo apt-get -y install luajit luajit-5.1-dev
sudo ln -sf /usr/bin/llc-12 /usr/bin/llc
if [ ! -d "bcc" ]; then
    git clone -b v0.24.0 https://gitee.com/mirrors/bcc.git
fi
export LLVM_ROOT="/usr/lib/llvm-12"
if [ ! -d  "bcc/build" ]; then
    mkdir bcc/build
fi
cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install