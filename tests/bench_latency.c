// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "perf_common.h"

/*
 * Generate a paced syscall workload and print its summary while the separate
 * collector measures event delivery latency.
 */
int main(int argc, char **argv)
{
	struct perf_options options;
	struct perf_pacer pacer;
	struct perf_result result = { 0 };
	int sink;
	perf_parse(argc, argv, &options);
	sink = open("/dev/null", O_WRONLY);
	if (sink < 0) { perror("/dev/null"); return 1; }
	perf_warmup(options.fixture, sink);
	perf_pacer_init(&pacer, &options, 3);
	while (result.transactions < options.max_transactions && perf_wait(&pacer)) {
		result.errors += perf_transaction(options.fixture, sink);
		result.transactions++;
	}
	result.start = pacer.start;
	result.end = perf_now();
	result.missed = pacer.missed;
	close(sink);
	perf_print("latency", &options, &result);
	return result.errors || !result.transactions;
}
