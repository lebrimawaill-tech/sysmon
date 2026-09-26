/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PERF_COMMON_H
#define PERF_COMMON_H
#include <stdbool.h>
#include <stdint.h>

struct perf_options {
	const char *fixture, *scenario, *operation;
	unsigned long rate, duration_ms, max_transactions, trial;
};
struct perf_pacer {
	uint64_t start, end, next, period, missed;
};
struct perf_result {
	uint64_t start, end, transactions, service_ns, errors, missed;
	uint64_t p50, p99;
};

/*
 * Return monotonic time in nanoseconds, terminating the benchmark if the clock
 * read fails.
 */
uint64_t perf_now(void);

/*
 * Set benchmark defaults and parse shared workload options, handling help, CSV
 * headers, and invalid arguments.
 */
void perf_parse(int argc, char **argv, struct perf_options *options);

/*
 * Set workload start/end times and the transaction period from the requested
 * syscall rate.
 */
void perf_pacer_init(struct perf_pacer *pacer, const struct perf_options *options,
		     unsigned int calls_per_transaction);

/*
 * Wait for the next transaction slot, skipping missed slots instead of
 * catching up; return false when the workload duration ends.
 */
bool perf_wait(struct perf_pacer *pacer);

/*
 * Open the fixture, read and write 64 bytes, then close it; return the number
 * of failed operations.
 */
unsigned int perf_transaction(const char *fixture, int sink);

/*
 * Run 20 transactions to warm the workload and check the fixture, exiting if
 * any operation fails.
 */
void perf_warmup(const char *fixture, int sink);

/*
 * Sort samples in place and select the p50 and p99 values; leave the
 * result unchanged for an empty sample set.
 */
void perf_percentiles(uint64_t *samples, unsigned long count, struct perf_result *result);

/*
 * Print a workload CSV row, calculating achieved rate from three monitored
 * syscalls per completed transaction.
 */
void perf_print(const char *suite, const struct perf_options *options,
		const struct perf_result *result);
#endif
