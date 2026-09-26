// SPDX-License-Identifier: GPL-2.0
#include "sysmon_internal.h"

/*
 * Allow the syscall immediately, before argument decoding, timestamps, PID
 * checks, or queue work.
 */
int sysmon_off(void)
{
	return 0;
}
NOKPROBE_SYMBOL(sysmon_off);
