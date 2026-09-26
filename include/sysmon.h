/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SYSMON_H
#define SYSMON_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
#endif

#define SYSMON_DEV	"/dev/sysmon"
#define SYSMON_MAGIC	0xE7
#define SYSMON_COMM_LEN	16

#define SYSMON_OFF	0
#define SYSMON_LOG	1
#define SYSMON_BLOCK	2

#define SYSMON_OPEN	1
#define SYSMON_READ	2
#define SYSMON_WRITE	3

struct sysmon_event {
	int			op;
	int			pid;
	char			comm[SYSMON_COMM_LEN];
	unsigned long long	mono_ns; /* CLOCK_MONOTONIC during selected record capture */
};

/* Native x86-64 binary capture record. read() returns ordinary log records;
 * GET_MATCH returns a dedicated FSM notification with the same payload.
 * Userspace formats the text log. args[] contains raw syscall arguments;
 * unused slots are zero. Open includes open/openat/openat2 (see name[]).
 * path[] is a best-effort nofault snapshot, truncated to PATH_LEN - 1;
 * "<unavailable>" means user memory could not be copied at probe time.
 * wall_ns is CLOCK_REALTIME; mono_ns is CLOCK_MONOTONIC at capture.
 * seq counts selected events, including drops. dropped is queue loss since
 * the last SET_MODE(OFF), sampled at capture; queued records keep their value.
 * Captures report syscall entry, not successful syscall completion.
 */
#define SYSMON_NAME_LEN		16
#define SYSMON_PATH_LEN		128
#define SYSMON_READ_MAX		32

struct sysmon_record {
	unsigned long long	wall_ns;
	unsigned long long	mono_ns;
	unsigned long long	seq;
	unsigned long long	dropped;
	int			pid;
	int			tid;
	int			op;
	int			blocked;
	char			comm[SYSMON_COMM_LEN];
	char			name[SYSMON_NAME_LEN];
	unsigned long		args[6];
	char			path[SYSMON_PATH_LEN];
	unsigned long long	watch; /* FSM watch token; zero for ordinary logging/blocking */
};

/* Stage totals since SYSMON_RESET_STATS; clocks are enabled by SET_TIMING.
 * drops is lifetime ring loss, unaffected by OFF or RESET_STATS. GET_DROPS
 * instead reports loss since the last OFF. overwrites stays zero.
 * capture_n includes FSM notification captures; enqueue_n counts ring entries,
 * write_n counts records delivered by read(). filtered_* are reserved (zero).
 * write_ns stays zero because the module does not write the log file.
 */
struct sysmon_stats {
	unsigned long long	capture_ns;
	unsigned long long	capture_n;
	unsigned long long	filtered_ns;
	unsigned long long	filtered_n;
	unsigned long long	enqueue_ns;
	unsigned long long	enqueue_n;
	unsigned long long	write_ns;
	unsigned long long	write_n;
	unsigned long long	drops;
	unsigned long long	overwrites;
	unsigned long long	queue_high;
};

/* Records accepted into the ring and copied out by read().
 * written_records counts records delivered to userspace. The log file is
 * written there. write_errors stays zero. write_batches counts read() calls
 * that returned at least one record.
 */
struct sysmon_log_progress {
	unsigned long long	accepted_records;
	unsigned long long	processed_records;
	unsigned long long	written_records;
	unsigned long long	write_errors;
	unsigned long long	write_batches;
};

/* SET commands pass the value in ioctl's arg. GET commands pass a pointer.
 * Events are read() as struct sysmon_record. LOG returns 0 so the syscall
 * body runs. BLOCK enqueues the record, then skips the body with -EPERM.
 */
#define SYSMON_SET_MODE		_IO(SYSMON_MAGIC, 1)
#define SYSMON_GET_MODE		_IOR(SYSMON_MAGIC, 2, int)
#define SYSMON_SET_PID		_IO(SYSMON_MAGIC, 3)
#define SYSMON_GET_PID		_IOR(SYSMON_MAGIC, 4, int)
#define SYSMON_SET_SYSCALL	_IO(SYSMON_MAGIC, 5)
#define SYSMON_GET_SYSCALL	_IOR(SYSMON_MAGIC, 6, int)
/* OFF resets this counter without discarding queued events or lifetime stats. */
#define SYSMON_GET_DROPS	_IOR(SYSMON_MAGIC, 8, unsigned long long)
#define SYSMON_SET_TIMING	_IO(SYSMON_MAGIC, 9)
#define SYSMON_RESET_STATS	_IO(SYSMON_MAGIC, 10)
#define SYSMON_GET_STATS	_IOR(SYSMON_MAGIC, 11, struct sysmon_stats)
#define SYSMON_GET_LOG_PROGRESS	_IOR(SYSMON_MAGIC, 12, struct sysmon_log_progress)
/* Opt in as the collector: exclude the calling thread group's syscalls until
 * this open file description is released. One collector file at a time;
 * repeating the ioctl on that file is harmless, another file gets EBUSY.
 * Only that thread group may read events from the collector descriptor.
 * This prevents collection from monitoring its own reads/writes.
 */
#define SYSMON_EXCLUDE_SELF	_IO(SYSMON_MAGIC, 13)

/* Collector-only, LOG-only FSM watch. Pass a pointer to an unsigned long long:
 * input is OPEN/READ/WRITE; output is a unique token for match notifications.
 * The kernel only selects events; state transitions belong to userspace.
 * SET_MODE and collector release clear the watch (ordinary LOG captures all).
 * Rebuild module and readers together when changing the record ABI.
 */
#define SYSMON_SET_WATCH		_IOWR(SYSMON_MAGIC, 14, unsigned long long)
#define SYSMON_GET_WATCH		_IOR(SYSMON_MAGIC, 15, unsigned long long)
#define SYSMON_WATCH_OP(watch)	((int)((watch) & 0xff))

/* Collector-only, non-consuming notification read. EAGAIN means no match yet.
 * poll(POLLPRI) reports a pending match independently of the lossy log ring.
 * The first matching entry is latched until SET_WATCH, SET_MODE or release;
 * repeated GET_MATCH and failed copies leave the notification intact.
 * FSM notifications are not delivered by the ordinary read()/POLLIN stream.
 */
#define SYSMON_GET_MATCH		_IOR(SYSMON_MAGIC, 16, struct sysmon_record)

/* Older names kept so existing tests still compile. */
#define SYSMON_SET_OP		SYSMON_SET_SYSCALL
#define SYSMON_GET_OP		SYSMON_GET_SYSCALL

#endif
