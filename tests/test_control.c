/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "sysmon.h"

/*
 * Return monotonic nanoseconds for control-operation deadlines, exiting if the
 * clock read fails.
 */
static unsigned long long monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (unsigned long long)now.tv_sec * 1000000000ULL +
	       (unsigned long long)now.tv_nsec;
}

/*
 * Sleep for the requested microseconds, resuming the remaining delay after a
 * signal.
 */
static void delay_us(unsigned long delay)
{
	struct timespec wait = {
		.tv_sec = (time_t)(delay / 1000000UL),
		.tv_nsec = (long)(delay % 1000000UL) * 1000L
	};

	while (nanosleep(&wait, &wait) && errno == EINTR)
		;
}

/*
 * Reset instrumentation, print a statistics snapshot, or wait for the stopped
 * module queue to drain.
 */
static int control(const char *operation)
{
	struct sysmon_log_progress progress;
	struct sysmon_stats stats;
	unsigned long long deadline = monotonic_ns() + 5000000000ULL;
	int result = EXIT_FAILURE;
	int fd = open(SYSMON_DEV, O_RDWR | O_CLOEXEC | O_NONBLOCK);

	if (fd < 0) {
		perror("open " SYSMON_DEV);
		return result;
	}
	if (!strcmp(operation, "--reset")) {
		if (ioctl(fd, SYSMON_SET_TIMING, 0UL) ||
		    ioctl(fd, SYSMON_RESET_STATS, 0UL))
			perror("reset instrumentation");
		else
			result = EXIT_SUCCESS;
	} else if (!strcmp(operation, "--snapshot")) {
		if (ioctl(fd, SYSMON_GET_STATS, &stats) ||
		    ioctl(fd, SYSMON_GET_LOG_PROGRESS, &progress)) {
			perror("read instrumentation");
		} else {
			printf("capture_n,accepted_records,delivered_records,dropped,queue_high,read_batches\n"
			       "%llu,%llu,%llu,%llu,%llu,%llu\n",
			       stats.capture_n, progress.accepted_records,
			       progress.written_records, stats.drops,
			       stats.queue_high, progress.write_batches);
			result = EXIT_SUCCESS;
		}
	} else {
		int mode;

		if (ioctl(fd, SYSMON_GET_MODE, &mode) || mode != SYSMON_OFF) {
			fprintf(stderr, "Drain requires the module to be off first.\n");
			goto out;
		}
		do {
			if (ioctl(fd, SYSMON_GET_LOG_PROGRESS, &progress)) {
				perror("read queue progress");
				goto out;
			}
			if (progress.accepted_records == progress.written_records) {
				result = EXIT_SUCCESS;
				goto out;
			}
			delay_us(1000);
		} while (monotonic_ns() < deadline);
		fprintf(stderr, "Collector did not drain the queue within five seconds.\n");
	}
out:
	close(fd);
	return result;
}

/*
 * Validate the requested reset, snapshot, or drain command and run it against
 * the module.
 */
int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "--reset") && strcmp(argv[1], "--snapshot") && strcmp(argv[1], "--drain"))) {
        fprintf(stderr, "Usage: %s --reset | --snapshot | --drain\n", argv[0]);
        return EXIT_FAILURE;
    }
    return control(argv[1]);
}
