// SPDX-License-Identifier: GPL-2.0
#include <linux/rcupdate.h>
#include "sysmon_internal.h"

/*
 * Dispatch each probe to OFF, LOG, or BLOCK handling, excluding the collector
 * and applying any active FSM watch.
 */
static int sysmon_pre(struct kprobe *kp, struct pt_regs *regs)
{
	u64 config = READ_ONCE(sysmon_config);
	int mode = SYSMON_MODE(config);
	const struct sysmon_probe *probe;

	if (mode == SYSMON_OFF)
		return sysmon_off();
	/* Exclude only the collector to prevent its read/write feedback loop. */
	if (sysmon_is_collector())
		return 0;
	probe = container_of(kp, struct sysmon_probe, kp);
	if (mode == SYSMON_LOG) {
		u64 watch = READ_ONCE(sysmon_watch);

		/* Ordinary LOG never consults the block rule. FSM selection is opt-in. */
		if (watch && (probe->op != SYSMON_WATCH_OP(watch) ||
			      !sysmon_match_claim(watch)))
			return 0;
		sysmon_capture(probe, regs, false, watch);
		return 0;
	}
	if (mode == SYSMON_BLOCK)
		return sysmon_block(probe, regs, config);
	return 0;
}
NOKPROBE_SYMBOL(sysmon_pre);

/*
 * Keep probes unoptimized so pre-handler instruction-pointer redirection
 * remains effective.
 *
 * Optprobes ignore pre_handler IP changes; a post handler disables them.
 */
static void sysmon_post(struct kprobe *kp, struct pt_regs *regs,
			unsigned long flags)
{
}
NOKPROBE_SYMBOL(sysmon_post);

#define SYSMON_PROBE(syscall, operation, argc, path_index) { \
	.kp = { .symbol_name = "__x64_sys_" #syscall, \
		.pre_handler = sysmon_pre, .post_handler = sysmon_post }, \
	.name = #syscall, .op = operation, .nargs = argc, .path_arg = path_index, \
}

static struct sysmon_probe probes[] = {
	SYSMON_PROBE(open, SYSMON_OPEN, 3, 0),
	SYSMON_PROBE(openat, SYSMON_OPEN, 4, 1),
	SYSMON_PROBE(openat2, SYSMON_OPEN, 4, 1),
	SYSMON_PROBE(read, SYSMON_READ, 3, -1),
	SYSMON_PROBE(write, SYSMON_WRITE, 3, -1),
};

/*
 * Register all supported syscall probes, removing earlier registrations if any
 * probe fails.
 */
int sysmon_probes_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(probes); i++) {
		ret = register_kprobe(&probes[i].kp);
		if (ret) {
			pr_err("sysmon: cannot probe %s: %d\n",
			       probes[i].kp.symbol_name, ret);
			while (--i >= 0)
				unregister_kprobe(&probes[i].kp);
			return ret;
		}
	}
	return 0;
}

/*
 * Unregister syscall probes and wait for tasks still returning through the
 * denial wrapper.
 */
void sysmon_probes_exit(void)
{
	int i;

	for (i = ARRAY_SIZE(probes) - 1; i >= 0; i--)
		unregister_kprobe(&probes[i].kp);
	/* A task can still be returning through sysmon_denied after its probe. */
	synchronize_rcu_tasks();
}
