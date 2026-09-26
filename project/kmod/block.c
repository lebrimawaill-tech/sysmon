// SPDX-License-Identifier: GPL-2.0
#include <linux/errno.h>
#include <linux/sched.h>
#include "sysmon_internal.h"

/*
 * Deny the syscall with -EPERM before its native wrapper executes.
 *
 * Entered in place of the native syscall wrapper, with its original stack. A
 * real compiled return observes the kernel's return-thunk conventions.
 * Changing only regs->ax at entry would NOT stop syscall side effects.
 */
static noinline notrace long sysmon_denied(const struct pt_regs *regs)
{
	return -EPERM;
}
NOKPROBE_SYMBOL(sysmon_denied);

/*
 * Capture a matching PID/operation denial and redirect execution to
 * sysmon_denied; return whether the syscall was blocked.
 */
int sysmon_block(const struct sysmon_probe *probe, struct pt_regs *regs,
		 u64 config)
{
	if (probe->op != SYSMON_OP(config) ||
	    task_tgid_nr(current) != SYSMON_PID(config))
		return 0;

	/* Queue loss must never change a blocking decision. */
	sysmon_capture(probe, regs, true, 0);
	instruction_pointer_set(regs, (unsigned long)sysmon_denied);
	return 1;
}
NOKPROBE_SYMBOL(sysmon_block);
