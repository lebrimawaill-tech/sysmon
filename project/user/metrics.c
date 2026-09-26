/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "sysmon_user.h"

#define SYSMON_METRICS_CAPACITY 262144U

struct sysmon_metric {
	unsigned long long seq;
	int pid;
	int tid;
	char syscall[SYSMON_NAME_LEN];
	int blocked;
	unsigned long long capture_ns;
	unsigned long long receive_ns;
	unsigned long long append_ns;
};

struct sysmon_metrics {
	FILE *file;
	struct sysmon_metric *rows;
	size_t count;
	unsigned long long overflow;
};

/*
 * Allocate a bounded measurement buffer and create a new CSV file without
 * overwriting existing data.
 */
struct sysmon_metrics *sysmon_metrics_open(const char *path)
{
	struct sysmon_metrics *metrics = calloc(1, sizeof(*metrics));
	int fd;

	if (!metrics)
		goto allocation_error;
	metrics->rows = calloc(SYSMON_METRICS_CAPACITY, sizeof(*metrics->rows));
	if (!metrics->rows) {
		free(metrics);
		goto allocation_error;
	}
	/* Refuse overwrite, symlinks, or aliases of the active sysmon.log. The
	 * caller opens this after collector exclusion, before changing mode. */
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0640);
	if (fd < 0) {
		fprintf(stderr, "Cannot create metrics file '%s': %s\n", path, strerror(errno));
		free(metrics->rows);
		free(metrics);
		return NULL;
	}
	metrics->file = fdopen(fd, "w");
	if (!metrics->file) {
		int saved_errno = errno;

		close(fd);
		fprintf(stderr, "Cannot open metrics stream: %s\n", strerror(saved_errno));
		free(metrics->rows);
		free(metrics);
		return NULL;
	}
	return metrics;

allocation_error:
	fprintf(stderr, "Cannot allocate performance measurement buffer: %s\n", strerror(errno));
	return NULL;
}

/*
 * Read a monotonic timestamp in nanoseconds, returning -1 if the clock read
 * fails.
 */
int sysmon_metrics_now(unsigned long long *ns)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
		fprintf(stderr, "Cannot get performance timestamp: %s\n", strerror(errno));
		return -1;
	}
	*ns = (unsigned long long)now.tv_sec * 1000000000ULL +
	      (unsigned long long)now.tv_nsec;
	return 0;
}

/*
 * Buffer event identity and capture/receive/append times, counting overflow
 * when the measurement buffer is full.
 */
void sysmon_metrics_record(struct sysmon_metrics *metrics,
			   const struct sysmon_record *record,
			   unsigned long long receive_ns,
			   unsigned long long append_ns)
{
	struct sysmon_metric *row;

	if (metrics->count == SYSMON_METRICS_CAPACITY) {
		++metrics->overflow;
		return;
	}
	row = &metrics->rows[metrics->count++];
	row->seq = record->seq;
	row->pid = record->pid;
	row->tid = record->tid;
	memcpy(row->syscall, record->name, sizeof(row->syscall));
	row->blocked = record->blocked;
	row->capture_ns = record->mono_ns;
	row->receive_ns = receive_ns;
	row->append_ns = append_ns;
}

/*
 * Write buffered measurements to CSV and release resources, reporting output
 * failures or buffer overflow.
 */
int sysmon_metrics_close(struct sysmon_metrics *metrics)
{
	size_t index;
	int result = 0;

	/* All CSV I/O happens after collection, so it cannot add one extra file
	 * write per observed event or contaminate the measured append latency. */
	if (fprintf(metrics->file,
		    "seq,pid,tid,syscall,blocked,capture_mono_ns,receive_mono_ns,append_mono_ns\n") < 0)
		result = -1;
	for (index = 0; !result && index < metrics->count; ++index) {
		const struct sysmon_metric *row = &metrics->rows[index];

		if (fprintf(metrics->file, "%llu,%d,%d,%.*s,%d,%llu,%llu,%llu\n",
			    row->seq, row->pid, row->tid, (int)sizeof(row->syscall),
			    row->syscall, row->blocked, row->capture_ns,
			    row->receive_ns, row->append_ns) < 0)
			result = -1;
	}
	if (fclose(metrics->file))
		result = -1;
	if (result)
		fprintf(stderr, "Cannot finish metrics CSV: %s\n", strerror(errno));
	printf("Performance metrics: %zu rows stored; %llu instrumentation overflow; capacity %u.\n",
	       metrics->count, metrics->overflow, SYSMON_METRICS_CAPACITY);
	if (metrics->overflow) {
		fprintf(stderr, "Performance measurement failed: metrics buffer overflowed by %llu events.\n",
			metrics->overflow);
		result = -1;
	}
	free(metrics->rows);
	free(metrics);
	return result;
}
