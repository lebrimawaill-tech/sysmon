// SPDX-License-Identifier: GPL-2.0
#include <linux/irq_work.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include "sysmon_internal.h"

/* One preallocated mailbox is enough: userspace arms one watch at a time.
 * There is no queue to overflow and no producer allocation. A reservation
 * selects one matching probe while it copies timestamps and arguments.
 */
static DEFINE_RAW_SPINLOCK(match_lock);
static DECLARE_WAIT_QUEUE_HEAD(match_wait);
static struct irq_work match_work;
static struct sysmon_record pending_match;
static bool claimed, ready;

/* Wake collectors waiting for a dedicated FSM match notification. */
static void sysmon_match_notify(struct irq_work *work)
{
	wake_up_interruptible_poll(&match_wait, EPOLLPRI);
}

/* Initialize deferred wakeups for the dedicated FSM match channel. */
void sysmon_match_init(void)
{
	init_irq_work(&match_work, sysmon_match_notify);
}

/* Wait for pending match notifications after probes have been removed. */
void sysmon_match_exit(void)
{
	/* All probes have been unregistered before synchronizing this work. */
	irq_work_sync(&match_work);
}

/*
 * Replace the active watch and clear any previous claim or match; the caller
 * must hold sysmon_control_mutex.
 */
void sysmon_match_arm(u64 watch)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&match_lock, flags);
	WRITE_ONCE(sysmon_watch, watch);
	claimed = false;
	ready = false;
	raw_spin_unlock_irqrestore(&match_lock, flags);
}

/*
 * Reserve the first match for the current watch, rejecting stale tokens and
 * duplicate claims.
 */
bool sysmon_match_claim(u64 watch)
{
	unsigned long flags;
	bool accepted = false;

	raw_spin_lock_irqsave(&match_lock, flags);
	if (watch && watch == sysmon_watch && !claimed) {
		claimed = true;
		accepted = true;
	}
	raw_spin_unlock_irqrestore(&match_lock, flags);
	return accepted;
}
NOKPROBE_SYMBOL(sysmon_match_claim);

/*
 * Store a claimed match if its watch is still current and schedule a collector
 * notification.
 */
void sysmon_match_publish(const struct sysmon_record *record)
{
	unsigned long flags;
	bool notify = false;

	raw_spin_lock_irqsave(&match_lock, flags);
	/* A delayed producer from an old watch must not overwrite a new match. */
	if (record->watch && record->watch == sysmon_watch && claimed && !ready) {
		pending_match = *record;
		ready = true;
		notify = true;
	}
	raw_spin_unlock_irqrestore(&match_lock, flags);
	if (notify)
		irq_work_queue(&match_work);
}
NOKPROBE_SYMBOL(sysmon_match_publish);

/*
 * Copy a pending match to the owning collector without consuming it, returning
 * EAGAIN when none is ready.
 */
long sysmon_match_get(struct file *file, void __user *out)
{
	struct sysmon_client *client = file->private_data;
	struct sysmon_record record;
	unsigned long flags;
	bool available;

	if (READ_ONCE(client->collector) != task_tgid(current))
		return -EACCES;
	raw_spin_lock_irqsave(&match_lock, flags);
	available = ready;
	if (available)
		record = pending_match;
	raw_spin_unlock_irqrestore(&match_lock, flags);
	if (!available)
		return -EAGAIN;
	/* No acknowledgment here. EFAULT and repeated reads preserve the match.
	 * Concurrent control changes are identified by the returned watch token.
	 */
	return copy_to_user(out, &record, sizeof(record)) ? -EFAULT : 0;
}

/*
 * Register a match waiter and report POLLPRI when a dedicated match is ready.
 */
__poll_t sysmon_match_poll(struct file *file, poll_table *wait)
{
	unsigned long flags;
	bool available;

	poll_wait(file, &match_wait, wait);
	raw_spin_lock_irqsave(&match_lock, flags);
	available = ready;
	raw_spin_unlock_irqrestore(&match_lock, flags);
	return available ? EPOLLPRI : 0;
}
