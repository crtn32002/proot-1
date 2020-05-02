#include <unistd.h>      /* get*id(2),  */
#include <linux/limits.h>
#include <errno.h>

#include "syscall/sysnum.h"
#include "extension/fake_id0/chown.h"
#include "extension/fake_id0/helper_functions.h"

int handle_chown_enter_end(Tracee *tracee, Config *config, Reg uid_sysarg, Reg gid_sysarg) {
	uid_t uid;
	gid_t gid;

	uid = peek_reg(tracee, ORIGINAL, uid_sysarg);
	gid = peek_reg(tracee, ORIGINAL, gid_sysarg);

	/* Swap actual and emulated ids to get a chance of
	 * success.  */
	if (uid == config->ruid)
		poke_reg(tracee, uid_sysarg, getuid());
	if (gid == config->rgid)
		poke_reg(tracee, gid_sysarg, getgid());

	return 0;
}
