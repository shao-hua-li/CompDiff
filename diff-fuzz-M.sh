#!/bin/bash

rm -rf "$OUT/findings"
mkdir -p "$OUT/findings"
chmod -R 777 "$OUT/findings"

export AFL_NO_UI=1
if [[ $FLAG_USE_FILE -eq 1 ]]; then
    if [[ $OUTPUT_FILE ]]; then
	old_output=$OUTPUT_FILE
	new_output="$OUT/findings/fuzzer0/$OUTPUT_FILE"
    else
   	 old_output=".output"
   	 new_output="$OUT/findings/fuzzer0/.output"
    fi
    ARGS=${ARGS/$old_output/$new_output}
    timeout $TIMEOUT "/$FUZZER/afl/afl-fuzz" -u $FLAG_USE_FILE -p $OUTPUT_FILE -c 10 -m none -t 1000+ -M fuzzer0 -b $AFFINITY -i "/$TARGET/corpus/" -o "$OUT/findings" $EXTRA_ARGS -- "/$TARGET/bin/$TARGET" $ARGS 2>&1
else
    timeout $TIMEOUT "/$FUZZER/afl/afl-fuzz" -c 10 -m none -t 1000+ -M fuzzer0 -b $AFFINITY -i "/$TARGET/corpus/" -o "$OUT/findings" $EXTRA_ARGS -- "/$TARGET/bin/$TARGET" $ARGS 2>&1
fi
