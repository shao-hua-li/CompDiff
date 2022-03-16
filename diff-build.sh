#!/bin/bash
set -e

if [ "$1" = "clean" ]; then
    cd "./afl"
    CC=clang make clean
    cd "llvm_mode"
    CC=clang AFL_TRACE_PC=1 make clean  
    cd ../../compilers
    make clean
    exit 0
fi

cd "./afl"
CC=clang make clean
LDFLAGS="-lcrypto -lssl" CC=clang make -j $(nproc)
cd "llvm_mode"
CC=clang AFL_TRACE_PC=1 make clean
CC=clang AFL_TRACE_PC=1 make -j $(nproc)
cd ..

"./afl-clang-fast++" $CXXFLAGS -std=c++11 -c "afl_driver.cpp" -fPIC -o "./afl_driver.o"
cd ..

cd "./compilers"
source build.sh
cd ..
