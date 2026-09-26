// SPDX-License-Identifier: GPL-2.0
#include <linux/irq_work.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include "sysmon_internal.h"

#define SYSMON_QUEUE_SIZE 4096

static struct sysmon_record *records;
static unsigned int head, tail, queued;
static u64 sequence, drops, drop_baseline;
/* Raw locks remain non-sleeping when the target kernel uses PREEMPT_RT. */
static DEFINE_RAW_SPINLOCK(queue_lock);
static DECLARE_WAIT_QUEUE_HEAD(log_wait);
static struct irq_work notify_work;
static struct sysmon_stats stats;
static struct sysmon_log_progress progress;

/* Wake ordinary event readers from deferred work outside the probe context. */
static void sysmon_notify(struct irq_work *work)
{
	wake_up_interruptible_poll(&log_wait, EPOLLIN | EPOLLRDNORM);
}

/*
 * Allocate the bounded event ring and initialize its deferred reader
 * notification.
 */
int sysmon_log_init(void)
{
	records = kvcalloc(SYSMON_QUEUE_SIZE, sizeof(*records), GFP_KERNEL);
	if (!records)
		return -ENOMEM;
	init_irq_work(&notify_work, sysmon_notify);
	return 0;
}

/* Wait for pending reader notifications and free the event ring. */
void sysmon_log_exit(void)
{
	irq_work_sync(&notify_work);
	kvfree(records);
}

/*
 * Copy a bounded user pathname without page faults, using a marker when the
 * address cannot be read.
 */
static void sysmon_capture_path(char *dst, const char __user *src)
{
	size_t i;

	/* Never fault in user pages from a kprobe; the original pointer is also
	 * preserved in args[]. Byte copies avoid crossing past a terminating NUL
	 * into an unmapped page. Long paths are truncated to PATH_LEN - 1 bytes.
	 */
	for (i = 0; i < SYSMON_PATH_LEN - 1; i++) {
		if (copy_from_user_nofault(dst + i, src + i, 1)) {
			strscpy(dst, "<unavailable>", SYSMON_PATH_LEN);
			return;
		}
		if (!dst[i])
			return;
	}
	dst[i] = '\0';
}
NOKPROBE_SYMBOL(sysmon_capture_path);

/*
 * Capture syscall metadata and timestamps, then publish a watch match or
 * enqueue an ordinary event with drop accounting.
 */
void sysmon_capture(const struct sysmon_probe *probe,
		    const struct pt_regs *regs, bool blocked, u64 watch)
{
	const struct pt_regs *args = (const struct pt_regs *)regs->di;
	struct sysmon_record record = { 0 };
	unsigned long flags;
	bool notify, timing = READ_ONCE(sysmon_timing);
	u64 start = 0, captured = 0;

	/* Capture time precedes argument/path copying and queue contention. */
	record.wall_ns = ktime_get_real_ns();
	record.mono_ns = ktime_get_ns();
	if (timing)
		start = record.mono_ns;
	record.pid = task_tgid_nr(current);
	record.tid = task_pid_nr(current);
	record.op = probe->op;
	record.blocked = blocked;
	record.watch = watch;
	/* current->comm is an advisory snapshot; avoid task_lock in a probe. */
	memcpy(record.comm, current->comm, sizeof(record.comm));
	record.comm[sizeof(record.comm) - 1] = '\0';
	strscpy(record.name, probe->name, sizeof(record.name));
	record.args[0] = args->di;
	record.args[1] = args->si;
	record.args[2] = args->dx;
	if (probe->nargs >= 4)
		record.args[3] = args->r10;
	if (probe->path_arg >= 0)
		sysmon_capture_path(record.path,
			(const char __user *)record.args[probe->path_arg]);
	if (timing)
		captured = ktime_get_ns();

	raw_spin_lock_irqsave(&queue_lock, flags);
	stats.capture_n++;
	if (timing)
		stats.capture_ns += captured - start;
	record.seq = ++sequence;
	record.dropped = drops - drop_baseline;
	if (watch) {
		/* A claimed FSM match never depends on ring capacity or read(). */
		raw_spin_unlock_irqrestore(&queue_lock, flags);
		sysmon_match_publish(&record);
		return;
	}
	if (queued == SYSMON_QUEUE_SIZE) {
		drops++;
		raw_spin_unlock_irqrestore(&queue_lock, flags);
		return;
	}
	notify = queued == 0;
	records[tail] = record;
	tail = (tail + 1) % SYSMON_QUEUE_SIZE;
	queued++;
	stats.enqueue_n++;
	stats.queue_high = max_t(u64, stats.queue_high, queued);
	if (timing)
		stats.enqueue_ns += ktime_get_ns() - captured;
	progress.accepted_records++;
	raw_spin_unlock_irqrestore(&queue_lock, flags);
	if (notify)
		irq_work_queue(&notify_work);
}
NOKPROBE_SYMBOL(sysmon_capture);

/*
 * Deliver a bounded batch of ring records to the owning collector, waiting for
 * data unless the file is nonblocking.
 */
ssize_t sysmon_log_read(struct file *file, char __user *buf,
		       size_t count, loff_t *pos)
{
	struct sysmon_client *client = file->private_data;
	struct sysmon_record *batch;
	unsigned int n, i;
	unsigned long flags;
	ssize_t ret;

	if (READ_ONCE(client->collector) != task_tgid(current))
		return -EACCES;
	if (!count)
		return 0;
	if (count < sizeof(*batch))
		return -EINVAL;
	n = min_t(size_t, count / sizeof(*batch), SYSMON_READ_MAX);
	batch = kmalloc_array(n, sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return -ENOMEM;
	ret = mutex_lock_interruptible(&client->read_mutex);
	if (ret)
		goto free_batch;
	while (!READ_ONCE(queued)) {
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto unlock;
		}
		ret = wait_event_interruptible(log_wait, READ_ONCE(queued));
		if (ret)
			goto unlock;
	}
	raw_spin_lock_irqsave(&queue_lock, flags);
	n = min(n, queued);
	for (i = 0; i < n; i++)
		batch[i] = records[(head + i) % SYSMON_QUEUE_SIZE];
	raw_spin_unlock_irqrestore(&queue_lock, flags);

	/* Single collector + read_mutex keeps head stable while copying. The
	 * producer drops new entries on overflow, never overwrites these slots.
	 * Failed copies therefore leave records available for a later read.
	 */
	if (copy_to_user(buf, batch, n * sizeof(*batch))) {
		ret = -EFAULT;
		goto unlock;
	}
	raw_spin_lock_irqsave(&queue_lock, flags);
	head = (head + n) % SYSMON_QUEUE_SIZE;
	queued -= n;
	progress.processed_records += n;
	progress.written_records += n;
	progress.write_batches++;
	stats.write_n += n;
	raw_spin_unlock_irqrestore(&queue_lock, flags);
	ret = n * sizeof(*batch);
unlock:
	mutex_unlock(&client->read_mutex);
free_batch:
	kfree(batch);
	return ret;
}

/*
 * Register collector wait queues and report ordinary-event or watch-match
 * readiness.
 */
__poll_t sysmon_log_poll(struct file *file, poll_table *wait)
{
	struct sysmon_client *client = file->private_data;

	if (READ_ONCE(client->collector) != task_tgid(current))
		return EPOLLERR;
	poll_wait(file, &log_wait, wait);
	return sysmon_match_poll(file, wait) |
	       (READ_ONCE(queued) ? EPOLLIN | EPOLLRDNORM : 0);
}

/* Copy a consistent snapshot of capture statistics and lifetime drops. */
void sysmon_log_stats(struct sysmon_stats *out)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&queue_lock, flags);
	*out = stats;
	out->drops = drops;
	raw_spin_unlock_irqrestore(&queue_lock, flags);
}

/* Return the number of dropped records since the drop baseline was reset. */
u64 sysmon_log_drops(void)
{
	unsigned long flags;
	u64 value;

	raw_spin_lock_irqsave(&queue_lock, flags);
	value = drops - drop_baseline;
	raw_spin_unlock_irqrestore(&queue_lock, flags);
	return value;
}

/*
 * Reset the reported drop count without changing lifetime totals or queued
 * records; capture must already be stopped and probes quiescent.
 */
void sysmon_log_reset_drops(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&queue_lock, flags);
	drop_baseline = drops;
	raw_spin_unlock_irqrestore(&queue_lock, flags);
}

/*
 * Copy a consistent snapshot of accepted records, delivered records, and read
 * batches.
 */
void sysmon_log_progress(struct sysmon_log_progress *out)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&queue_lock, flags);
	*out = progress;
	raw_spin_unlock_irqrestore(&queue_lock, flags);
}

/*
 * Clear optional capture statistics and initialize the high-water mark to the
 * current queue depth.
 */
void sysmon_log_reset_stats(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&queue_lock, flags);
	memset(&stats, 0, sizeof(stats));
	stats.queue_high = queued;
	raw_spin_unlock_irqrestore(&queue_lock, flags);
}
