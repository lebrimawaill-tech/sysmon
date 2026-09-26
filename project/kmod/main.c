// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include "sysmon_internal.h"

u64 sysmon_config = SYSMON_CONFIG(SYSMON_OFF, SYSMON_OPEN, 0);
u64 sysmon_watch;
DEFINE_MUTEX(sysmon_control_mutex);
struct pid __rcu *sysmon_collector;
bool sysmon_timing;

static struct miscdevice sysmon_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sysmon",
	.fops = &sysmon_fops,
	.mode = 0600,
};

/*
 * Initialize event delivery, register probes, and expose the device, unwinding
 * completed steps on failure.
 */
static int __init sysmon_init(void)
{
	int ret;

	ret = sysmon_log_init();
	if (ret)
		return ret;
	sysmon_match_init();
	ret = sysmon_probes_init();
	if (ret)
		goto free_log;
	ret = misc_register(&sysmon_device);
	if (ret)
		goto remove_probes;
	pr_info("sysmon: loaded in off mode; control and events at /dev/sysmon\n");
	return 0;

remove_probes:
	sysmon_probes_exit();
free_log:
	sysmon_match_exit();
	sysmon_log_exit();
	return ret;
}

/*
 * Disable capture, remove the device and probes, and release event-delivery
 * resources.
 */
static void __exit sysmon_exit(void)
{
	/* Open device descriptors pin THIS_MODULE, including a running collector. */
	WRITE_ONCE(sysmon_config, SYSMON_CONFIG(SYSMON_OFF, SYSMON_OPEN, 0));
	misc_deregister(&sysmon_device);
	sysmon_probes_exit();
	sysmon_match_exit();
	sysmon_log_exit();
	pr_info("sysmon: unloaded\n");
}

module_init(sysmon_init);
module_exit(sysmon_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("sysmon contributors");
MODULE_DESCRIPTION("Kprobe syscall monitor with ioctl-controlled off/log/block modes");
