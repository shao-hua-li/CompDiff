#!/bin/bash
set -e

if [ -z $1 ]; then
    echo "[!] Please pass the build script for your target."
    exit 1
fi

COMDIFFDIR=$(dirname $(realpath "$0"))
# firstly, build fuzz binary
export compiler_nm=fuzz
unset DIFF_ID
export CC=${COMDIFFDIR}/aflpp/afl-clang-fast
export CXX=${COMDIFFDIR}/aflpp/afl-clang-fast++
source $1

# secondly, build binaries with different opt flags
id=0
for cc in `ls ${COMDIFFDIR}/compilers/diff-cc-*`; do
    export CC=$cc
    export CXX=${cc//-cc-/-cxx-}
    export DIFF_ID=${id}
    cd ${COMDIFFDIR}
    source $1
    id=$((id+1))
done

