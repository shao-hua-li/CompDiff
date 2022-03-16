#!/bin/bash

# Step 0, prepare the location and name of the sourcecode
BASEDIR=$(dirname $(realpath "$1"))/src/pdftotext # where the source code locates
BINDIR=$(dirname $(realpath "$1"))/bin      # where the fuzzing binary locatates, typically is a symbolic link, see Step3
if [ -z ${DIFF_ID} ]; then
    BASEDIR+="-fuzz"
else
    BASEDIR+="-${DIFF_ID}"
fi
rm -rf ${BASEDIR}

# Step 1, prepare the target sourcecode. 
# If you don't have public accessible URL for your target, you can just use `cp` to make a copy.
mkdir -p ${BASEDIR}
cd ${BASEDIR}
wget https://dl.xpdfreader.com/xpdf-4.03.tar.gz
tar -xzf xpdf-4.03.tar.gz
mv xpdf-4.03 xpdf
rm xpdf-4.03.tar.gz

# Step 2, compile the target
cd xpdf
cmake .
make -j

# Step 3, link the target binary
# It is important to guarantee that binaries compiled from
# diff-cc-* can be found in the same location with the fuzz target.
# 
mkdir -p ${BINDIR}
if [ -z ${DIFF_ID} ]; then
    ln -sf ${BASEDIR}/xpdf/xpdf/pdftotext ${BINDIR}/pdftotext
else
    ln -sf ${BASEDIR}/xpdf/xpdf/pdftotext ${BINDIR}/pdftotext-${DIFF_ID}
fi
