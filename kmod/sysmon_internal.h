/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SYSMON_INTERNAL_H
#define SYSMON_INTERNAL_H

#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include "sysmon.h"

#ifndef CONFIG_X86_64
#error "sysmon currently supports native x86-64 syscall wrappers only"
#endif

/* One atomic snapshot prevents a probe from observing a torn configuration. */
#define SYSMON_CONFIG(mode, op, pid) \
	((u64)(mode) | ((u64)(op) << 8) | ((u64)(pid) << 32))
#define SYSMON_MODE(config) ((int)((config) & 0xff))
#define SYSMON_OP(config)   ((int)(((config) >> 8) & 0xff))
#define SYSMON_PID(config)  ((pid_t)((config) >> 32))

extern u64 sysmon_config;
extern u64 sysmon_watch;
extern struct mutex sysmon_control_mutex;
extern struct pid __rcu *sysmon_collector;
extern bool sysmon_timing;

/* Initialize deferred wakeups for the dedicated FSM match channel. */
void sysmon_match_init(void);

/* Wait for pending match notifications after probes have been removed. */
void sysmon_match_exit(void);

/*
 * Replace the active watch and clear any previous claim or match; the caller
 * must hold sysmon_control_mutex.
 */
void sysmon_match_arm(u64 watch);

/*
 * Reserve the first match for the current watch, rejecting stale tokens and
 * duplicate claims.
 */
bool sysmon_match_claim(u64 watch);

/*
 * Store a claimed match if its watch is still current and schedule a collector
 * notification.
 */
void sysmon_match_publish(const struct sysmon_record *record);

/*
 * Copy a pending match to the owning collector without consuming it, returning
 * EAGAIN when none is ready.
 */
long sysmon_match_get(struct file *file, void __user *out);

/*
 * Register a match waiter and report POLLPRI when a dedicated match is ready.
 */
__poll_t sysmon_match_poll(struct file *file, poll_table *wait);

struct sysmon_client {
	struct pid *collector;
	struct mutex read_mutex;
};

struct sysmon_probe {
	struct kprobe kp;
	const char *name;
	int op;
	int nargs;
	int path_arg; /* -1 for read/write */
};

/*
 * Check under RCU whether the current process owns collection and must be
 * excluded from capture.
 */
static inline bool sysmon_is_collector(void)
{
	bool excluded;

	rcu_read_lock();
	excluded = rcu_dereference(sysmon_collector) == task_tgid(current);
	rcu_read_unlock();
	return excluded;
}

/*
 * Register all supported syscall probes, removing earlier registrations if any
 * probe fails.
 */
int sysmon_probes_init(void);

/*
 * Unregister syscall probes and wait for tasks still returning through the
 * denial wrapper.
 */
void sysmon_probes_exit(void);

/*
 * Allow the syscall immediately, before argument decoding, timestamps, PID
 * checks, or queue work.
 */
int sysmon_off(void);

/*
 * Capture a matching PID/operation denial and redirect execution to
 * sysmon_denied; return whether the syscall was blocked.
 */
int sysmon_block(const struct sysmon_probe *probe, struct pt_regs *regs,
		 u64 config);

/*
 * Capture syscall metadata and timestamps, then publish a watch match or
 * enqueue an ordinary event with drop accounting.
 */
void sysmon_capture(const struct sysmon_probe *probe,
		    const struct pt_regs *regs, bool blocked, u64 watch);

/*
 * Allocate the bounded event ring and initialize its deferred reader
 * notification.
 */
int sysmon_log_init(void);

/* Wait for pending reader notifications and free the event ring. */
void sysmon_log_exit(void);

/*
 * Deliver a bounded batch of ring records to the owning collector, waiting for
 * data unless the file is nonblocking.
 */
ssize_t sysmon_log_read(struct file *file, char __user *buf,
		       size_t count, loff_t *pos);

/*
 * Register collector wait queues and report ordinary-event or watch-match
 * readiness.
 */
__poll_t sysmon_log_poll(struct file *file, poll_table *wait);

/* Copy a consistent snapshot of capture statistics and lifetime drops. */
void sysmon_log_stats(struct sysmon_stats *stats);

/* Return the number of dropped records since the drop baseline was reset. */
u64 sysmon_log_drops(void);

/*
 * Reset the reported drop count without changing lifetime totals or queued
 * records; capture must already be stopped and probes quiescent.
 */
void sysmon_log_reset_drops(void);

/*
 * Copy a consistent snapshot of accepted records, delivered records, and read
 * batches.
 */
void sysmon_log_progress(struct sysmon_log_progress *progress);

/*
 * Clear optional capture statistics and initialize the high-water mark to the
 * current queue depth.
 */
void sysmon_log_reset_stats(void);

extern const struct file_operations sysmon_fops;
#endif
