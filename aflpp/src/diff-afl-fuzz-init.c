/*
   american fuzzy lop++ - initialization related routines
   ------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#include "cmplog.h"


void setup_stdout_file_diff(afl_state_t *afl) {

  if (afl->flag_use_output) {
    OKF("Using output...%s", afl->output_file);
    u8* fn = alloc_printf("%s", afl->output_file);
    unlink(fn); /* Ignore errors */

    afl->fsrv.dev_stdout_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (afl->fsrv.dev_stdout_fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_free(fn);

    fn = alloc_printf("%s/.error", afl->tmp_dir);
    unlink(fn); /* Ignore errors */

    afl->fsrv.dev_stderr_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (afl->fsrv.dev_stderr_fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_free(fn);
  }

  for (int idx_com=0; idx_com < afl->diff_num; idx_com++) {
    u8* fn = alloc_printf("%s/.cur_output_%d", afl->tmp_dir, idx_com);

    unlink(fn); /* Ignore errors */

    afl->diff_fsrv[idx_com].dev_stdout_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (afl->diff_fsrv[idx_com].dev_stdout_fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_free(fn);
  }

  for (int idx_com=0; idx_com < afl->diff_num; idx_com++) {
    u8* fn = alloc_printf("%s/.cur_error_%d", afl->tmp_dir, idx_com);

    unlink(fn); /* Ignore errors */

    afl->diff_fsrv[idx_com].dev_stderr_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (afl->diff_fsrv[idx_com].dev_stderr_fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_free(fn);
  }
  

}
