#!/bin/bash
# This is the building script for different compiler configurations.

make clean

if [ "$1" = "clean" ]; then
    exit 0
fi

forksrv=202
id=0

compiler_id=0
for _ in $(seq 1 `jq "[.][0] | length" config`); do
    for config in `jq "[[.][0][${compiler_id}].configs][0][]" config`; do
        export DIFF_CC=`jq "[.][0][${compiler_id}].CC" config`
        export DIFF_CXX=`jq "[.][0][${compiler_id}].CXX" config`
        export DIFF_ID=${id}
        printf "#define FORKSRV_FD ${forksrv} \n #define DIFF_ID ${DIFF_ID} \n #define DIFF_CC ${DIFF_CC} \n #define DIFF_CXX ${DIFF_CXX} \n #define DIFF_CONFIG ${config} " > ./compiler-base/diff-config.h
        make
        id=$((id+1))
        forksrv=$((forksrv+4))
    done
    compiler_id=$((compiler_id+1))
done

# for config in `jq "[.clang.configs][0][]" config`; do
#     export DIFF_CC=`jq ".clang.CC" config`
#     export DIFF_CXX=`jq ".clang.CXX" config`
#     export DIFF_ID=${id}
#     printf "#define FORKSRV_FD ${forksrv} \n #define DIFF_ID ${DIFF_ID} \n #define DIFF_CC ${DIFF_CC} \n #define DIFF_CXX ${DIFF_CXX} \n #define DIFF_CONFIG ${config} " > ./compiler-base/diff-config.h
#     make
#     id=$((id+1))
#     forksrv=$((forksrv+4))
# done

# for config in `jq "[.gcc.configs][0][]" config`; do
#     export DIFF_CC=`jq ".gcc.CC" config`
#     export DIFF_CXX=`jq ".gcc.CXX" config`
#     export DIFF_ID=${id}
#     printf "#define FORKSRV_FD ${forksrv} \n #define DIFF_ID ${DIFF_ID} \n #define DIFF_CC ${DIFF_CC} \n #define DIFF_CXX ${DIFF_CXX} \n #define DIFF_CONFIG ${config} " > ./compiler-base/diff-config.h
#     make
#     id=$((id+1))
#     forksrv=$((forksrv+4))
# done
