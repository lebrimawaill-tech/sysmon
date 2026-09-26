// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "perf_common.h"

/*
 * Measure completed transaction times under the selected load and print
 * response percentiles, excluding pacing sleeps.
 *
 * Baseline and every monitored mode use the same two clocks per transaction.
 */
int main(int argc, char **argv)
{
	struct perf_options options;
	struct perf_pacer pacer;
	struct perf_result result = { 0 };
	uint64_t *samples;
	int sink;
	perf_parse(argc, argv, &options);
	samples = calloc(options.max_transactions, sizeof(*samples));
	if (!samples) { perror("samples"); return 1; }
	sink = open("/dev/null", O_WRONLY);
	if (sink < 0) { perror("/dev/null"); free(samples); return 1; }
	perf_warmup(options.fixture, sink);
	perf_pacer_init(&pacer, &options, 3);
	while (result.transactions < options.max_transactions && perf_wait(&pacer)) {
		uint64_t start = perf_now(), elapsed;
		result.errors += perf_transaction(options.fixture, sink);
		elapsed = perf_now() - start;
		samples[result.transactions++] = elapsed;
		result.service_ns += elapsed;
	}
	result.start = pacer.start;
	result.end = perf_now();
	result.missed = pacer.missed;
	close(sink);
	perf_percentiles(samples, result.transactions, &result);
	free(samples);
	perf_print("impact", &options, &result);
	return result.errors || !result.transactions;
}
