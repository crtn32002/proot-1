#include <linux/limits.h>
#include <sys/types.h>   /* uid_t, gid_t, get*id(2), */
#include <unistd.h>	  /* get*id(2),  */
#include <assert.h>	  /* assert(3), */

#include "tracee/mem.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "extension/fake_id0/stat.h"
#include "extension/fake_id0/helper_functions.h"

int handle_stat_exit_end(Tracee *tracee, Config *config, Reg stat_sysarg) {
	word_t address;
	uid_t uid;
	gid_t gid;
	word_t result;

	/* Override only if it succeed.  */
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result != 0)
		return 0;

	address = peek_reg(tracee, ORIGINAL, stat_sysarg);

	/* Sanity checks.  */
	assert(__builtin_types_compatible_p(uid_t, uint32_t));
	assert(__builtin_types_compatible_p(gid_t, uint32_t));

	/* Get the uid & gid values from the 'stat' structure.  */
	uid = peek_uint32(tracee, address + offsetof_stat_uid(tracee));
	if (errno != 0)
		uid = 0; /* Not fatal.  */

	gid = peek_uint32(tracee, address + offsetof_stat_gid(tracee));
	if (errno != 0)
		gid = 0; /* Not fatal.  */

	/* Override only if the file is owned by the current user.
	 * Errors are not fatal here.  */
	if (uid == getuid())
		poke_uint32(tracee, address + offsetof_stat_uid(tracee), config->suid);

	if (gid == getgid())
		poke_uint32(tracee, address + offsetof_stat_gid(tracee), config->sgid);

	return 0;
}
