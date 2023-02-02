#!/bin/bash
set -e

if [ "$1" = "clean" ]; then
    cd "./aflpp"
    CC=clang make clean
    cd ../compilers
    make clean
    exit 0
fi

cd "./aflpp"
CC=clang make source-only
CC=clang make -C utils/aflpp_driver
cd ..

cd "./compilers"
source build.sh
cd ..
