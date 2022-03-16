#!/bin/bash

# Step 0, prepare the location and name of the sourcecode
BASEDIR=$(dirname $(realpath "$1"))/src/libtiff # where the source code locates
BINDIR=$(dirname $(realpath "$1"))/bin      # where the fuzzing binary locatates, typically is a symbolic link, see Step3
if [ -z ${DIFF_ID} ]; then
    BASEDIR+="-fuzz"
else
    BASEDIR+="-${DIFF_ID}"
fi
rm -rf ${BASEDIR}

# Step 1, prepare the target sourcecode. 
# If you don't have public accessible URL for your target, you can just use `cp` to make a copy.
git clone https://gitlab.com/libtiff/libtiff.git ${BASEDIR}


# Step 2, compile the target
cd ${BASEDIR}
./autogen.sh
./configure --disable-shared
make -j$(nproc) clean
make -j$(nproc) all

# Step 3, link the target binary
# It is important to guarantee that binaries compiled from
# diff-cc-* can be found in the same location with the fuzz target.
# 
mkdir -p ${BINDIR}
if [ -z ${DIFF_ID} ]; then
    ln -sf ${BASEDIR}/tools/tiffcp ${BINDIR}/tiffcp
else
    ln -sf ${BASEDIR}/tools/tiffcp ${BINDIR}/tiffcp-${DIFF_ID}
fi
