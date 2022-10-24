#!/bin/bash -e
add-apt-repository -y ppa:ubuntu-toolchain-r/test
apt-get update && apt-get -y install gcc-11 g++-11 libssl-dev gcc-11-plugin-dev libc++-dev libc++abi-dev jq

wget https://apt.llvm.org/llvm.sh
chmod +x ./llvm.sh
./llvm.sh 13
rm ./llvm.sh

