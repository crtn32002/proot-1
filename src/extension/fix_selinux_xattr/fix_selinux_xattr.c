/*
 * Author: Unrud
 * Date:   18/12/2018
 *
 * Description: An extension that changes the return
 * value of setxattr from EACCES or EPERM to ENOTSUP
 * when trying to write security.selinux.
 */

#include <sys/xattr.h>
#include "extension/extension.h"
#include "tracee/mem.h"

const unsigned int MAX_NAME_LENGTH = 17;

/**
 * Return ENOTSUP instead of EACCES or EPERM
 * when trying to write security.selinux.
 */
static int handle_setxattr(Tracee *tracee)
{
    Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
    switch (sysnum) {
    case PR_setxattr: 
    case PR_lsetxattr:
    case PR_fsetxattr: {
        /* get the result of the syscall */
        word_t res = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        /* EACCESS is also returned, when access to the file is denied */
        if (res != -EACCES && res != -EPERM) {
            return 0;
        }

        /* get the system call arguments */
        word_t name_start = peek_reg(tracee, CURRENT, SYSARG_2);

        /* check if the attribute name is security.selinux */
        char name[MAX_NAME_LENGTH];
        int status = read_string(tracee, name, name_start, MAX_NAME_LENGTH);
        if (status < 0) {
            return status;
        }
        if (strncmp("security.selinux", name, MAX_NAME_LENGTH) != 0) {
            return 0;
        }

        poke_reg(tracee, SYSARG_RESULT, -ENOTSUP);
        return 0;
    }

    default:
        return 0;
    }
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occured.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int fix_selinux_xattr_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case INITIALIZATION: {
        /* List of syscalls handled by this extension */
        static FilteredSysnum filtered_sysnums[] = {
            { PR_setxattr,   FILTER_SYSEXIT },
            { PR_lsetxattr,  FILTER_SYSEXIT },
            { PR_fsetxattr,  FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_CHAINED_EXIT:
    case SYSCALL_EXIT_END: {
        return handle_setxattr(TRACEE(extension));
    }

    default:
        return 0;
    }
}
