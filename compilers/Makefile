#
# american fuzzy lop - LLVM instrumentation
# -----------------------------------------
#
# Written by Laszlo Szekeres <lszekeres@google.com> and
#            Michal Zalewski <lcamtuf@google.com>
#
# LLVM integration design comes from Laszlo Szekeres.
#
# Copyright 2015, 2016 Google LLC All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

CFLAGS      ?= -O3 -funroll-loops
CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign
ifdef AFL_TRACE_PC
  CFLAGS    += -DUSE_TRACE_PC=1
endif

CXXFLAGS    ?= -O3 -funroll-loops
CXXFLAGS    += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
               -DVERSION=\"$(VERSION)\" -Wno-variadic-macros

# User teor2345 reports that this is required to make things work on MacOS X.

ifeq "$(shell uname)" "Darwin"
  CLANG_LFL += -Wl,-flat_namespace -Wl,-undefined,suppress
endif

# We were using llvm-config --bindir to get the location of clang, but
# this seems to be busted on some distros, so using the one in $PATH is
# probably better.

ifeq "$(origin CC)" "default"
  CC         = clang
  CXX        = clang++
endif

PROGS      = ./diff-cc ./diff-llvm-rt.o

all: test_deps $(PROGS) test_build all_done

test_deps:
ifndef DIFF_CC
	@echo "[!] Don't use Makefile, use build.sh (\$$DIFF_CC not defined)"; exit 1
	@echo "[-] Define \$$DIFF_CC !"; exit 1
else ifndef DIFF_CXX
	@echo "[!] Don't use Makefile, use build.sh (\$$DIFF_CXX not defined)"; exit 1
else ifndef DIFF_ID
	@echo "[!] Don't use Makefile, use build.sh (\$$DIFF_ID not defined)"; exit 1
endif
	@echo "[*] Checking for working '$(CC)'..."
	@which $(CC) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(CC)'. Make sure that it's in your \$$PATH (or set \$$CC and \$$CXX)."; exit 1 )
	@echo "[*] Checking for working '$(DIFF_CC)'..."
	@which $(DIFF_CC) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(DIFF_CC)'. Make sure that it's in your \$$PATH (or set \$$DIFF_CC and \$$DIFF_CXX)."; exit 1 )
	@echo "[*] Checking for working '$(DIFF_CXX)'..."
	@which $(DIFF_CXX) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(DIFF_CXX)'. Make sure that it's in your \$$PATH (or set \$$DIFF_CC and \$$DIFF_CXX)."; exit 1 )
	@echo "[+] All set and ready to build."


./diff-cc: ./compiler-base/diff-cc.c | test_deps
	$(CC) $(CFLAGS) $< -o diff-cc-$(DIFF_ID) $(LDFLAGS)
	ln -sf diff-cc-$(DIFF_ID)  ./diff-cxx-$(DIFF_ID) 

./diff-llvm-rt.o: ./compiler-base/diff-llvm-rt.o.c | test_deps
	$(CC) $(CFLAGS) -fPIC -c $< -o diff-llvm-rt-$(DIFF_ID).o

test_build: $(PROGS)
	@echo "[*] Testing the CC wrapper and instrumentation output..."
	unset AFL_USE_ASAN AFL_USE_MSAN AFL_INST_RATIO; ./diff-cc-$(DIFF_ID) $(CFLAGS) ./compiler-base/test-instr.c -o ./compiler-base/test-instr $(LDFLAGS)
# Use /dev/null to avoid problems with optimization messing up expected
# branches. See https://github.com/google/AFL/issues/30.
	@echo "[+] All right, the instrumentation seems to be working!"

all_done: test_build
	@echo "[+] All done! You can now use './diff-cc-$(DIFF_ID)' to compile programs."

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* ./compiler-base/test-instr ./compiler-base/.test-instr0 ./compiler-base/.test-instr1 
	rm -f ./diff-cc-* ./diff-cxx-* ./diff-llvm-rt-*
