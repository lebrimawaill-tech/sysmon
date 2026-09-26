// SPDX-License-Identifier: GPL-2.0
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/pid_namespace.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "sysmon_internal.h"

/* Serialized by sysmon_control_mutex; never reuse a token during this load. */
static u64 watch_generation;

/* Require host administration privileges and allocate per-open device state. */
static int sysmon_open(struct inode *inode, struct file *file)
{
	struct sysmon_client *client;

	/* Host PIDs and system-wide syscall data require host administration. */
	if (!capable(CAP_SYS_ADMIN) || task_active_pid_ns(current) != &init_pid_ns)
		return -EPERM;
	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;
	mutex_init(&client->read_mutex);
	file->private_data = client;
	return nonseekable_open(inode, file);
}

/*
 * Release collector ownership, disarm its watch, and free per-open device
 * state.
 */
static int sysmon_release(struct inode *inode, struct file *file)
{
	struct sysmon_client *client = file->private_data;
	struct pid *pid = client->collector;

	if (pid) {
		mutex_lock(&sysmon_control_mutex);
		sysmon_match_arm(0);
		RCU_INIT_POINTER(sysmon_collector, NULL);
		/* Keep ownership serialized until probe readers have finished. */
		synchronize_rcu();
		put_pid(pid);
		mutex_unlock(&sysmon_control_mutex);
	}
	kfree(client);
	return 0;
}

/*
 * Validate and handle device requests for configuration, collector ownership,
 * match delivery, and statistics.
 */
static long sysmon_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	struct sysmon_client *client = file->private_data;
	void __user *out = (void __user *)arg;
	struct sysmon_stats stats;
	struct sysmon_log_progress progress;
	u64 config, watch, drops;
	int value, ret = 0;

	if (!capable(CAP_SYS_ADMIN) || task_active_pid_ns(current) != &init_pid_ns)
		return -EPERM;

	/* Getters do not serialize with independent readers or copy under a lock. */
	config = READ_ONCE(sysmon_config);
	switch (cmd) {
	case SYSMON_GET_MODE:
		value = SYSMON_MODE(config);
		return copy_to_user(out, &value, sizeof(value)) ? -EFAULT : 0;
	case SYSMON_GET_PID:
		value = SYSMON_PID(config);
		return copy_to_user(out, &value, sizeof(value)) ? -EFAULT : 0;
	case SYSMON_GET_SYSCALL:
		value = SYSMON_OP(config);
		return copy_to_user(out, &value, sizeof(value)) ? -EFAULT : 0;
	case SYSMON_GET_WATCH:
		watch = READ_ONCE(sysmon_watch);
		return copy_to_user(out, &watch, sizeof(watch)) ? -EFAULT : 0;
	case SYSMON_GET_MATCH:
		return sysmon_match_get(file, out);
	case SYSMON_GET_DROPS:
		drops = sysmon_log_drops();
		return copy_to_user(out, &drops, sizeof(drops)) ? -EFAULT : 0;
	case SYSMON_GET_STATS:
		sysmon_log_stats(&stats);
		return copy_to_user(out, &stats, sizeof(stats)) ? -EFAULT : 0;
	case SYSMON_GET_LOG_PROGRESS:
		sysmon_log_progress(&progress);
		return copy_to_user(out, &progress, sizeof(progress)) ? -EFAULT : 0;
	}

	if (mutex_lock_interruptible(&sysmon_control_mutex))
		return -ERESTARTSYS;
	config = READ_ONCE(sysmon_config);
	switch (cmd) {
	case SYSMON_SET_MODE:
		if (arg > SYSMON_BLOCK ||
		    (arg == SYSMON_BLOCK && SYSMON_PID(config) == 0)) {
			ret = -EINVAL;
			break;
		}
		WRITE_ONCE(sysmon_config, SYSMON_CONFIG(arg, SYSMON_OP(config),
						      SYSMON_PID(config)));
		sysmon_match_arm(0);
		if (arg == SYSMON_OFF) {
			/* Kprobe handlers run with preemption/IRQs disabled. Wait
			 * for old captures before resetting their drop baseline;
			 * the control mutex prevents concurrent re-enabling.
			 */
			synchronize_rcu();
			sysmon_log_reset_drops();
		}
		break;
	case SYSMON_SET_WATCH:
		if (client->collector != task_tgid(current)) {
			ret = -EACCES;
			break;
		}
		if (SYSMON_MODE(config) != SYSMON_LOG) {
			ret = -EINVAL;
			break;
		}
		if (copy_from_user(&watch, out, sizeof(watch))) {
			ret = -EFAULT;
			break;
		}
		if (watch < SYSMON_OPEN || watch > SYSMON_WRITE) {
			ret = -EINVAL;
			break;
		}
		if (watch_generation == (U64_MAX >> 8)) {
			ret = -EOVERFLOW;
			break;
		}
		watch |= (watch_generation + 1) << 8;
		if (copy_to_user(out, &watch, sizeof(watch))) {
			ret = -EFAULT;
			break;
		}
		watch_generation++;
		sysmon_match_arm(watch);
		break;
	case SYSMON_SET_PID:
		/* Zero clears the target, except while blocking is active. */
		if (arg > INT_MAX || (arg == 0 && SYSMON_MODE(config) == SYSMON_BLOCK)) {
			ret = -EINVAL;
			break;
		}
		WRITE_ONCE(sysmon_config, SYSMON_CONFIG(SYSMON_MODE(config),
						      SYSMON_OP(config), arg));
		break;
	case SYSMON_SET_SYSCALL:
		if (arg < SYSMON_OPEN || arg > SYSMON_WRITE) {
			ret = -EINVAL;
			break;
		}
		WRITE_ONCE(sysmon_config, SYSMON_CONFIG(SYSMON_MODE(config), arg,
						      SYSMON_PID(config)));
		break;
	case SYSMON_SET_TIMING:
		if (arg > 1)
			ret = -EINVAL;
		else
			WRITE_ONCE(sysmon_timing, (bool)arg);
		break;
	case SYSMON_RESET_STATS:
		sysmon_log_reset_stats();
		break;
	case SYSMON_EXCLUDE_SELF:
		if (client->collector) {
			if (client->collector != task_tgid(current))
				ret = -EBUSY;
			break;
		}
		if (rcu_access_pointer(sysmon_collector)) {
			ret = -EBUSY;
			break;
		}
		client->collector = get_pid(task_tgid(current));
		rcu_assign_pointer(sysmon_collector, client->collector);
		break;
	default:
		ret = -ENOTTY;
	}
	mutex_unlock(&sysmon_control_mutex);
	return ret;
}

const struct file_operations sysmon_fops = {
	.owner = THIS_MODULE,
	.open = sysmon_open,
	.release = sysmon_release,
	.unlocked_ioctl = sysmon_ioctl,
	.read = sysmon_log_read,
	.poll = sysmon_log_poll,
};
