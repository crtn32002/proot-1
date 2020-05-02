#include <linux/limits.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "extension/fake_id0/config.h"
#include "extension/fake_id0/helper_functions.h"

/** Reads a path from path_sysarg into path.
 */
int read_sysarg_path(Tracee *tracee, char path[PATH_MAX], Reg path_sysarg, RegVersion version)
{
	int size;
	char original[PATH_MAX];
	/** Current is already canonicalized. . Modified is used here
	 *  for exit calls because on ARM architectures, the result to a system
	 *  call is placed in SYSARG_1. Using MODIFIED allows the original path to
	 *  be read. ORIGINAL is necessary in the case of execve(2) because of the
	 *  modifications that PRoot makes to the path of the executable.
	 */
	switch(version) {
		case MODIFIED:
			size = read_string(tracee, path, peek_reg(tracee, MODIFIED, path_sysarg), PATH_MAX);
			break;
		case CURRENT:
			size = read_string(tracee, path, peek_reg(tracee, CURRENT, path_sysarg), PATH_MAX);
			break;
		case ORIGINAL:
			size = read_string(tracee, original, peek_reg(tracee, ORIGINAL, path_sysarg), PATH_MAX);
			translate_path(tracee, path, AT_FDCWD, original, true);
			break;
		/* Never hit */
		default:
			size = 0;   //Shut the compiler up
			break;
	}

	if(size < 0)
		return size;
	if(size >= PATH_MAX)
		return -ENAMETOOLONG;

	/** If a path does not belong to the guestfs, a handler either exits with 0
	 *  or sets the syscall to void (in the case of chmod and chown). Checking
	 *  whether or not a path belongs to the guestfs only needs to happen if
	 *  that path actually exists. Removing this check will cause some package
	 *  installations to fail because they try to create symlinks with null
	 *  targets.
	 */
	if(strlen(path) > 0)
		if(!belongs_to_guestfs(tracee, path))
			return 1;

	return 0;
}

/** Gets a path without its final component.
 */
int get_dir_path(char path[PATH_MAX], char dir_path[PATH_MAX])
{
	int offset;

	strcpy(dir_path, path);
	offset = strlen(dir_path) - 1;
	if (offset > 0) {
		/* Skip trailing path separators. */
		while (offset > 1 && dir_path[offset] == '/')
			offset--;

		/* Search for the previous path separator. */
		while (offset > 1 && dir_path[offset] != '/')
			offset--;

		/* Cut the end of the string before the last component. */
		dir_path[offset] = '\0';
	}
	return 0;
}

void modify_pid_status_files(Tracee *tracee, Config *config, char translated_path[PATH_MAX]) {
	char new_path[PATH_MAX];
	char new_translated_path[PATH_MAX];
	char dir_path[PATH_MAX];
	char dir_path_translated[PATH_MAX];
	char *str, *s;
	struct stat statBuf;
	FILE *fp_in, *fp_out;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	/* Make sure this is a system call and file of interest */
	word_t sysnum = get_sysnum(tracee, ORIGINAL);
	if ((sysnum != PR_open) && (sysnum != PR_openat))
		return;

	if (strncmp(translated_path, "/proc", 5) != 0)
		return;

	if (strlen(translated_path) < 7)
		return;

	if (strcmp(translated_path + strlen(translated_path) - 7, "/status") != 0)
		return;

	strcpy(new_path, "/support");
	strcat(new_path, translated_path);

	/* Create directory and copy file to new location */
	get_dir_path(new_path, dir_path);
	s = dir_path;
	while ((str = strtok(s, "/")) != NULL) {
		if (str != s) {
			str[-1] = '/';
		}
		if (stat (dir_path, &statBuf) == -1) {
			translate_path(tracee, dir_path_translated, AT_FDCWD, dir_path, true);
			mkdir (dir_path_translated, 0700);
		} else {
			return;
		}
		s = NULL;
	}

	translate_path(tracee, new_translated_path, AT_FDCWD, new_path, true);

	fp_in = fopen(translated_path, "r");
	if (fp_in == NULL) {
		return;
	}

	fp_out = fopen(new_translated_path, "w");
	if (fp_out == NULL) {
		return;
	}

	while ((read = getline(&line, &len, fp_in)) != -1) {
		if (strncmp(line, "Uid:", 4) == 0) {
			fprintf(fp_out, "Uid:   %d   %d   %d   %d\n", config->euid, config->euid, config->euid, config->euid);
		} else if (strncmp(line, "Gid:", 4) == 0) {
			fprintf(fp_out, "Gid:   %d   %d   %d   %d\n", config->egid, config->egid, config->egid, config->egid);
		} else {
			fprintf(fp_out, "%s", line);
		}
	}

	fclose(fp_in);
	fclose(fp_out);
	if (line)
		free(line);

	/* Change path to point at the new file */
	strcpy(translated_path, new_translated_path);
	return;
}
