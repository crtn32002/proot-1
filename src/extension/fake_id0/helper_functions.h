#ifndef FAKE_ID0_HELPER_FUNCTIONS_H
#define FAKE_ID0_HELPER_FUNCTIONS_H

#include <linux/limits.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "extension/fake_id0/config.h"

int get_dir_path(char path[PATH_MAX], char dir_path[PATH_MAX]);

int read_sysarg_path(Tracee *tracee, char path[PATH_MAX], Reg path_sysarg, RegVersion version);

void modify_pid_status_files(Tracee *tracee, Config *config, char translated_path[PATH_MAX]);

#endif /* FAKE_ID0_HELPER_FUNCTIONS_H */
