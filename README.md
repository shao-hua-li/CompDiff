# CompDiff

CompDiff is a tool that backends the research paper [Finding Unstable Code via Compiler-Driven Differential Testing](https://shao-hua-li.github.io/files/2023-ASPLOS-CompDiff.pdf) published in ASPLOS 2023.

## Building CompDiff

Clone this repository and cd to the root directory, then run `preinstall.sh` to install necessary packages.

To build:
```shell
$ ./diff-build.sh
```
By default, this script will build 10 different compiler configurations `clang-O0`, `-O1`, `-O2`, `-O3`, `-Os`, and `gcc-O0`, `-O1`, `-O2`, `-O3`, `-Os`. You can edit the configuration in `./compilers/config` to specify compiler configurations. For example,
```json
    {
        "CC": "/usr/bin/clang", // CC path
        "CXX": "/usr/bin/clang++",  // CXX path
        "configs": [
            "-O0",  // compiler flags
            "-O1"
        ]
    },
```
Now, you will find 10 different C/C++ compiler instances (`diff-cc-*` / `diff-cxx-*`) in `./compilers/`. Next, you will need to use them to instrument your target.

## Instrumenting Binaries
We provide `diff-instrument.sh` for instrumenting with different compiler configurations built from last step.
It requires the building script for the target as the parameter.

We provide two example scripts in [examples/xpdf](examples/xpdf)  and [examples/libtiff](examples/libtiff). For example, to build `pdftotext`, run
```
$ ./diff-instrument.sh ./examples/xpdf/build.sh
```
After instrumenting, you will find 10 binaries in [examples/xpdf/bin/](examples/xpdf/bin)  , where `pdftotext` is the normal AFL intrumented binary and `pdftotext-*` are CompDiff instrumented binaries.
Please refer to these example building scripts for a detailed explanation.
It's importance to make sure that these binaries are located in the same path and have such format.


## Fuzzing
To fuzz `xpdf` with CompDiff, run
```
$ ./aflpp/afl-fuzz -y 10 -i examples/xpdf/seeds -o examples/xpdf/findings -- ./examples/xpdf/bin/pdftotext @@ -
```
`-y` means the number of compiler configurations will be used. All found bug-triggering inputs will be saved to `examples/xpdf/findings/default/diffs`.
Since `pdftotext` emits output to stdout, CompDiff automatically catch them. For those that outputs are written to files, one need to use `-Y` to specify the output file name.

For example, to fuzz `libtiff`, run
```
$ ./aflpp/afl-fuzz -y 10 -i examples/libtiff/seeds -o examples/libtiff/findings -Y "out.file" -- ./examples/libtiff/bin/tiffcp -M -i @@ out.file
```
where `-Y "out.file"` tells CompDiff that the target will use "out.file" as the output file.

## Post-processing
There might be many input files that are saved due to small timeouts or randomness in program outputs.
We provide a python script to filter our these cases.
For example, the following scirpt is to filter inputs found in `xpdf`
```
$ python3 diff-post.py --bin ./examples/xpdf/bin/pdftotext --args "@@ -" -y 10 -r 1 -i examples/xpdf/findings/diffs -o ./out
```

and this scirpt for `libtiff`
```
$ python3 diff-post.py --bin ./examples/libtiff/bin/tiffcp --args "-M -i @@ out.file" --out_file "out.file" -y 10 -r 1 -i examples/libtiff/findings/diffs -o ./out
```
The inputs that indeed trigger bugs will be saved to `./out/diffs/` and their outputs are available in `./out/outputs/`. Timeout intputs will be saved to `./out/timeouts`.
Please run `python3 diff-post.py -h` for help information.

