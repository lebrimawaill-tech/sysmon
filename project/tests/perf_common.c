// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "perf_common.h"

/*
 * Return monotonic time in nanoseconds, terminating the benchmark if the clock
 * read fails.
 */
uint64_t perf_now(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * Parse an unsigned decimal option within the supplied bounds, exiting on
 * invalid input.
 */
static unsigned long number(const char *text, unsigned long min, unsigned long max)
{
	char *end;
	unsigned long value;
	errno = 0;
	value = strtoul(text, &end, 10);
	if (!*text || strspn(text, "0123456789") != strlen(text) || *end ||
	    errno || value < min || value > max) {
		fprintf(stderr, "Invalid number: %s (expected %lu..%lu)\n", text, min, max);
		exit(EXIT_FAILURE);
	}
	return value;
}

/*
 * Set benchmark defaults and parse shared workload options, handling help, CSV
 * headers, and invalid arguments.
 */
void perf_parse(int argc, char **argv, struct perf_options *options)
{
	enum { FIXTURE = 256, SCENARIO, RATE, DURATION, MAXIMUM, TRIAL, OPERATION, HEADER };
	static const struct option flags[] = {
		{ "fixture", required_argument, NULL, FIXTURE },
		{ "scenario", required_argument, NULL, SCENARIO },
		{ "rate", required_argument, NULL, RATE },
		{ "duration-ms", required_argument, NULL, DURATION },
		{ "max-transactions", required_argument, NULL, MAXIMUM },
		{ "trial", required_argument, NULL, TRIAL },
		{ "operation", required_argument, NULL, OPERATION },
		{ "header", no_argument, NULL, HEADER },
		{ "help", no_argument, NULL, 'h' }, { NULL, 0, NULL, 0 }
	};
	int flag;
	*options = (struct perf_options) {
		.scenario = "verbose", .operation = "write", .rate = 3000,
		.duration_ms = 250, .max_transactions = 20000, .trial = 1
	};
	while ((flag = getopt_long(argc, argv, "h", flags, NULL)) != -1) {
		switch (flag) {
		case FIXTURE: options->fixture = optarg; break;
		case SCENARIO: options->scenario = optarg; break;
		case RATE: options->rate = number(optarg, 0, 1000000000); break;
		case DURATION: options->duration_ms = number(optarg, 1, 60000); break;
		case MAXIMUM: options->max_transactions = number(optarg, 1, 1000000); break;
		case TRIAL: options->trial = number(optarg, 1, 1000000); break;
		case OPERATION: options->operation = optarg; break;
		case HEADER:
			puts("suite,scenario,trial,pid,requested_rate,achieved_rate,transactions,start_ns,end_ns,elapsed_ns,service_mean_ns,response_p50_ns,response_p99_ns,missed_slots,errors");
			exit(EXIT_SUCCESS);
		case 'h':
			printf("Usage: %s --fixture PATH [--scenario NAME] [--trial N]\n"
			       "  [--rate SYSCALLS_PER_SECOND] [--duration-ms N] [--max-transactions N]\n"
			       "Rate 0 means maximum speed. Defaults: 3000/s, 250 ms, cap 20000.\n"
			       "Impact excludes pacing sleeps from response times. --header prints CSV header.\n"
			       "test_block additionally accepts --operation open|read|write.\n", argv[0]);
			exit(EXIT_SUCCESS);
		default: exit(EXIT_FAILURE);
		}
	}
	if (!options->fixture || optind != argc || !*options->scenario ||
	    strspn(options->scenario, "abcdefghijklmnopqrstuvwxyz0123456789_") != strlen(options->scenario) ||
	    (strcmp(options->operation, "open") && strcmp(options->operation, "read") &&
	     strcmp(options->operation, "write"))) {
		fprintf(stderr, "Provide --fixture, a valid scenario, and operation open/read/write.\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * Set workload start/end times and the transaction period from the requested
 * syscall rate.
 */
void perf_pacer_init(struct perf_pacer *p, const struct perf_options *options,
		     unsigned int calls_per_transaction)
{
	*p = (struct perf_pacer) { .start = perf_now() };
	p->end = p->start + options->duration_ms * 1000000ULL;
	p->next = p->start;
	p->period = options->rate ? 1000000000ULL * calls_per_transaction / options->rate : 0;
}

/*
 * Wait for the next transaction slot, skipping missed slots instead of
 * catching up; return false when the workload duration ends.
 */
bool perf_wait(struct perf_pacer *p)
{
	uint64_t now = perf_now();
	if (now >= p->end)
		return false;
	if (p->period) {
		/* Skip missed slots instead of producing a misleading catch-up burst. */
		if (p->next != p->start && p->next < now) {
			uint64_t missed = (now - p->next) / p->period + 1;
			p->next += missed * p->period;
			p->missed += missed;
		}
		uint64_t target = p->next < p->end ? p->next : p->end;
		if (target > now) {
			struct timespec ts = { .tv_sec = target / 1000000000ULL,
				.tv_nsec = target % 1000000000ULL };
			int error;
			do {
				error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
			} while (error == EINTR);
			if (error) {
				errno = error;
				perror("clock_nanosleep");
				exit(EXIT_FAILURE);
			}
		}
		if (p->next >= p->end) return false;
		p->next += p->period;
	}
	return perf_now() < p->end;
}

/*
 * Open the fixture, read and write 64 bytes, then close it; return the number
 * of failed operations.
 */
unsigned int perf_transaction(const char *fixture, int sink)
{
	char bytes[64] = { 0 };
	unsigned int errors = 0;
	long fd = syscall(SYS_open, fixture, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) ++errors;
	if (syscall(SYS_read, fd, bytes, sizeof(bytes)) != sizeof(bytes)) ++errors;
	if (syscall(SYS_write, sink, bytes, sizeof(bytes)) != sizeof(bytes)) ++errors;
	if (fd >= 0 && syscall(SYS_close, fd)) ++errors;
	return errors;
}

/*
 * Run 20 transactions to warm the workload and check the fixture, exiting if
 * any operation fails.
 */
void perf_warmup(const char *fixture, int sink)
{
	for (int i = 0; i < 20; i++) {
		if (perf_transaction(fixture, sink)) {
			fprintf(stderr, "Warmup failed; fixture must contain at least 64 readable bytes.\n");
			exit(EXIT_FAILURE);
		}
	}
}

/* Compare two unsigned 64-bit samples for ascending qsort order. */
static int compare(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

/*
 * Sort samples in place and select the p50 and p99 values; leave the
 * result unchanged for an empty sample set.
 */
void perf_percentiles(uint64_t *samples, unsigned long count, struct perf_result *result)
{
	if (!count) return;
	qsort(samples, count, sizeof(*samples), compare);
	result->p50 = samples[(count - 1) * 50 / 100];
	result->p99 = samples[(count - 1) * 99 / 100];
}

/*
 * Print a workload CSV row, calculating achieved rate from three monitored
 * syscalls per completed transaction.
 */
void perf_print(const char *suite, const struct perf_options *o, const struct perf_result *r)
{
	uint64_t elapsed = r->end - r->start;
	printf("%s,%s,%lu,%d,%lu,%.3f,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
	       ",%.3f,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
	       suite, o->scenario, o->trial, getpid(), o->rate,
	       elapsed ? 3e9 * r->transactions / elapsed : 0, r->transactions,
	       r->start, r->end, elapsed, r->transactions ? (double)r->service_ns / r->transactions : 0,
	       r->p50, r->p99, r->missed, r->errors);
}
