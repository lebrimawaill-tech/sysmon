/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "sysmon_user.h"

/*
 * Validate CLI options, configure the device, run optional event collection,
 * and close logs, metrics, and device resources.
 */
int main(int argc, char **argv)
{
	struct sysmon_options options;
	struct sysmon_config config = { .mode = -1, .pid = -1, .syscall = -1 };
	FILE *log_file = NULL;
	struct sysmon_metrics *metrics = NULL;
	struct sysmon_fsm fsm;
	int mode, pid, op, parsed, fd;
	int result = EXIT_FAILURE;

	parsed = sysmon_parse_commands(argc, argv, &options);
	if (parsed) {
		sysmon_usage(parsed > 0 ? stdout : stderr, argv[0]);
		return parsed > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	/* Parse before touching the device or changing the active mode. */
	if (options.fsm_path && sysmon_fsm_load(options.fsm_path, &fsm))
		return EXIT_FAILURE;
	if (options.fsm_path)
		fsm.once = options.once;
	fd = open(SYSMON_DEV, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", SYSMON_DEV, strerror(errno));
		return EXIT_FAILURE;
	}
	/* Explicit modes need no previous rule: --block supplied its own target. */
	if (options.mode == -1 && sysmon_get_config(fd, &config))
		goto out;
	mode = options.mode == -1 ? config.mode : options.mode;
	pid = options.pid == -1 ? config.pid : options.pid;
	if (mode == SYSMON_BLOCK) {
		op = options.syscall == -1 ? config.syscall : options.syscall;
		if (pid <= 0 || op < SYSMON_OPEN || op > SYSMON_WRITE) {
			fprintf(stderr, "Invalid block configuration; use --block --pid PID --syscall open|read|write.\n");
			goto out;
		}
	}
	if (options.collect) {
		if (mode == SYSMON_BLOCK && pid == (int)getpid()) {
			fprintf(stderr, "The collector cannot also be the process being blocked.\n");
			goto out;
		}
		/* Claim the reader before opening the log or enabling observation. */
		if (ioctl(fd, SYSMON_EXCLUDE_SELF, 0UL) < 0) {
			fprintf(stderr, "Cannot claim event collector: %s\n", strerror(errno));
			goto out;
		}
		log_file = sysmon_open_log();
		if (!log_file)
			goto out;
		if (options.metrics_path) {
			metrics = sysmon_metrics_open(options.metrics_path);
			if (!metrics)
				goto out;
		}
	}
	if (sysmon_apply_commands(fd, &options)) {
		fprintf(stderr, "Earlier successful settings may remain; inspect --status.\n");
		goto out;
	}
	if (options.fsm_path && sysmon_fsm_start(fd, log_file, &fsm))
		goto out;
	if (sysmon_get_config(fd, &config))
		goto out;
	sysmon_print_config(&config);
	if (options.collect) {
		printf("Appending events to ./sysmon.log. Press Ctrl-C to stop collection.\n");
		if (fflush(stdout) ||
		    sysmon_collect(fd, log_file, metrics,
				   options.fsm_path ? &fsm : NULL))
			goto out;
	}
	result = EXIT_SUCCESS;
out:
	if (metrics && sysmon_metrics_close(metrics))
		result = EXIT_FAILURE;
	if (log_file && fclose(log_file)) {
		fprintf(stderr, "Cannot finish sysmon.log: %s\n", strerror(errno));
		result = EXIT_FAILURE;
	}
	if (close(fd)) {
		fprintf(stderr, "Cannot close %s: %s\n", SYSMON_DEV, strerror(errno));
		result = EXIT_FAILURE;
	}
	return result;
}
