/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "sysmon_user.h"

/* Return the printable mode name, or "unknown" for an unrecognized value. */
const char *sysmon_mode_name(int mode)
{
	switch (mode) {
	case SYSMON_OFF: return "off";
	case SYSMON_LOG: return "log";
	case SYSMON_BLOCK: return "block";
	default: return "unknown";
	}
}

/*
 * Return the printable syscall category, or "unset" for an unrecognized value.
 */
const char *sysmon_op_name(int op)
{
	switch (op) {
	case SYSMON_OPEN: return "open";
	case SYSMON_READ: return "read";
	case SYSMON_WRITE: return "write";
	default: return "unset";
	}
}

/* Write command-line usage and supported options to the requested stream. */
void sysmon_usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s [--pid PID] [--syscall open|read|write]\n"
		"          [--block | --log | --off] [--collect] [--status]\n"
		"          [--metrics PATH] [--file [PATH]]\n"
		"\n"
		"  --pid PID          Set the process ID (thread-group ID) to block.\n"
		"  --syscall NAME     Select the operation to block.\n"
		"  --block            Block the selected process/operation and collect events.\n"
		"  --log              Log every observed open/read/write and collect events.\n"
		"  --file [PATH]      With --log, run the FSM from PATH (default fsm.json).\n"
		"                     JSON: {\"states\": [\"open\", \"read\", \"write\"]}\n"
		"  --once             With --log --file, stop in off mode after one cycle.\n"
		"  --off              Show pre-reset drops, disable monitoring and reset the count.\n"
		"  --collect          Collect events without changing the current mode.\n"
		"  --status           Print configuration; suppress automatic collection.\n"
		"  --metrics PATH     Save optional performance timestamps to a new CSV file.\n"
		"                     Requires collection; holds up to 262144 rows in memory.\n"
		"  --help             Show this help.\n"
		"\n"
		"Events append to ./sysmon.log with capture and append timestamps.\n"
		"--pid/--syscall configure blocking only; ordinary log mode logs all operations.\n"
		"Every --block command requires explicit --pid PID and --syscall NAME.\n"
		"Blocked entries are red (ANSI).\n"
		"Ctrl-C stops collection; use --off separately to disable monitoring.\n",
		program);
}

/* Parse a strictly positive decimal process ID that fits in an int. */
static int parse_pid(const char *text, int *pid)
{
	const char *cursor;
	char *end;
	long value;

	if (!*text)
		return -1;
	for (cursor = text; *cursor; ++cursor) {
		if (*cursor < '0' || *cursor > '9')
			return -1;
	}
	errno = 0;
	value = strtol(text, &end, 10);
	if (errno || *end || value <= 0 || value > INT_MAX)
		return -1;
	*pid = (int)value;
	return 0;
}

/*
 * Parse and validate CLI options; return zero for success, positive for help,
 * or negative for invalid arguments.
 */
int sysmon_parse_commands(int argc, char **argv, struct sysmon_options *options)
{
	enum { OPT_PID = 256, OPT_SYSCALL, OPT_BLOCK, OPT_LOG, OPT_OFF,
	       OPT_COLLECT, OPT_STATUS, OPT_METRICS, OPT_FILE, OPT_ONCE };
	static const struct option long_options[] = {
		{ "pid", required_argument, NULL, OPT_PID },
		{ "syscall", required_argument, NULL, OPT_SYSCALL },
		{ "block", no_argument, NULL, OPT_BLOCK },
		{ "log", no_argument, NULL, OPT_LOG },
		{ "off", no_argument, NULL, OPT_OFF },
		{ "collect", no_argument, NULL, OPT_COLLECT },
		{ "status", no_argument, NULL, OPT_STATUS },
		{ "metrics", required_argument, NULL, OPT_METRICS },
		{ "file", optional_argument, NULL, OPT_FILE },
		{ "once", no_argument, NULL, OPT_ONCE },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	bool help = false;
	int option;

	*options = (struct sysmon_options) {
		.mode = -1, .pid = -1, .syscall = -1
	};
	opterr = 0;
	while ((option = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
		switch (option) {
		case OPT_PID:
			if (options->pid != -1 || parse_pid(optarg, &options->pid)) {
				fprintf(stderr, "--pid requires one positive decimal PID.\n");
				return -1;
			}
			break;
		case OPT_SYSCALL:
			if (options->syscall != -1) {
				fprintf(stderr, "Specify --syscall only once.\n");
				return -1;
			}
			if (!strcmp(optarg, "open"))
				options->syscall = SYSMON_OPEN;
			else if (!strcmp(optarg, "read"))
				options->syscall = SYSMON_READ;
			else if (!strcmp(optarg, "write"))
				options->syscall = SYSMON_WRITE;
			else {
				fprintf(stderr, "Unknown syscall '%s'; use open, read, or write.\n", optarg);
				return -1;
			}
			break;
		case OPT_BLOCK:
		case OPT_LOG:
		case OPT_OFF:
			if (options->mode != -1) {
				fprintf(stderr, "Choose only one of --block, --log, and --off.\n");
				return -1;
			}
			options->mode = option == OPT_BLOCK ? SYSMON_BLOCK :
				       option == OPT_LOG ? SYSMON_LOG : SYSMON_OFF;
			break;
		case OPT_COLLECT: options->collect = true; break;
		case OPT_STATUS: options->status = true; break;
		case OPT_ONCE: options->once = true; break;
		case OPT_FILE:
			if (options->fsm_path) {
				fprintf(stderr, "Specify --file only once.\n");
				return -1;
			}
			if (!optarg && optind < argc && argv[optind][0] != '-')
				optarg = argv[optind++];
			options->fsm_path = optarg ? optarg : "fsm.json";
			if (!*options->fsm_path) {
				fprintf(stderr, "--file requires a nonempty path.\n");
				return -1;
			}
			break;
		case OPT_METRICS:
			if (options->metrics_path || !*optarg) {
				fprintf(stderr, "--metrics requires one nonempty output path.\n");
				return -1;
			}
			options->metrics_path = optarg;
			break;
		case 'h': help = true; break;
		default:
			fprintf(stderr, "Unknown option or missing argument near '%s'.\n",
				argv[optind > 0 ? optind - 1 : 0]);
			return -1;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		return -1;
	}
	if (help)
		return 1;
	if (options->once && !options->fsm_path) {
		fprintf(stderr, "--once requires --log --file.\n");
		return -1;
	}
	if (options->fsm_path && (options->mode != SYSMON_LOG || options->status)) {
		fprintf(stderr, "--file requires --log and cannot be combined with --status.\n");
		return -1;
	}
	if (options->mode == SYSMON_BLOCK &&
	    (options->pid == -1 || options->syscall == -1)) {
		fprintf(stderr, "--block requires both --pid PID and --syscall open|read|write on this command.\n");
		return -1;
	}
	if (options->mode == SYSMON_OFF && options->collect) {
		fprintf(stderr, "--off cannot be combined with --collect.\n");
		return -1;
	}
	if (!options->status &&
	    (options->mode == SYSMON_LOG || options->mode == SYSMON_BLOCK))
		options->collect = true;
	if (options->metrics_path && !options->collect) {
		fprintf(stderr, "--metrics requires --collect or automatic --log/--block collection.\n");
		return -1;
	}
	if (options->mode == -1 && options->pid == -1 && options->syscall == -1 &&
	    !options->collect && !options->status) {
		fprintf(stderr, "Specify a configuration change, --collect, or --status.\n");
		return -1;
	}
	return 0;
}

/*
 * Read an ioctl result into the supplied output buffer and report failures
 * using the setting name.
 */
static int get_value(int fd, unsigned long command, void *value, const char *name)
{
	if (ioctl(fd, command, value) < 0) {
		fprintf(stderr, "Cannot get %s: %s\n", name, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Read the current mode, drop count, and mode-specific block rule or FSM
 * watch.
 */
int sysmon_get_config(int fd, struct sysmon_config *config)
{
	*config = (struct sysmon_config) { .pid = -1, .syscall = -1 };
	if (get_value(fd, SYSMON_GET_MODE, &config->mode, "mode"))
		return -1;
	if (config->mode == SYSMON_LOG &&
	    get_value(fd, SYSMON_GET_WATCH, &config->watch, "FSM watch"))
		return -1;
	/* The target and operation have no meaning in off/log mode. */
	if (config->mode == SYSMON_BLOCK &&
	    (get_value(fd, SYSMON_GET_PID, &config->pid, "PID") ||
	     get_value(fd, SYSMON_GET_SYSCALL, &config->syscall, "syscall")))
		return -1;
	return get_value(fd, SYSMON_GET_DROPS, &config->drops, "drop count");
}

/* Send a scalar ioctl setting and report failures using the setting name. */
static int set_value(int fd, unsigned long command, int value, const char *name)
{
	/* This ABI passes SET values directly, not pointers to the values. */
	if (ioctl(fd, command, (unsigned long)value) < 0) {
		fprintf(stderr, "Cannot set %s: %s\n", name, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Apply requested settings in an order that avoids enabling an incomplete
 * block rule.
 */
int sysmon_apply_commands(int fd, const struct sysmon_options *options)
{
	unsigned long long drops_before_off = 0;

	/* Snapshot before OFF resets the kernel counter. Print after disabling
	 * so this console write cannot generate another monitored event.
	 */
	if (options->mode == SYSMON_OFF &&
	    get_value(fd, SYSMON_GET_DROPS, &drops_before_off, "pre-reset drop count"))
		return -1;
	/* Leave blocking before updating its unused settings for off/log mode. */
	if ((options->mode == SYSMON_OFF || options->mode == SYSMON_LOG) &&
	    set_value(fd, SYSMON_SET_MODE, options->mode, "mode"))
		return -1;
	if (options->mode == SYSMON_OFF)
		printf("Dropped before reset (snapshot): %llu\n\n", drops_before_off);
	if (options->pid != -1 && set_value(fd, SYSMON_SET_PID, options->pid, "PID"))
		return -1;
	if (options->syscall != -1 &&
	    set_value(fd, SYSMON_SET_SYSCALL, options->syscall, "syscall"))
		return -1;
	if (options->mode == SYSMON_BLOCK &&
	    set_value(fd, SYSMON_SET_MODE, options->mode, "mode"))
		return -1;
	return 0;
}

/* Print the active configuration and warn when records have been dropped. */
void sysmon_print_config(const struct sysmon_config *config)
{
	printf("Current mode: %s; dropped: %llu\n",
	       sysmon_mode_name(config->mode), config->drops);
	if (config->mode == SYSMON_BLOCK)
		printf("Blocking syscall: %s; target PID: %d\n",
		       sysmon_op_name(config->syscall), config->pid);
	if (config->mode == SYSMON_LOG && config->watch)
		printf("FSM watching syscall: %s; watch=%llu (state controlled by collector).\n",
		       sysmon_op_name(SYSMON_WATCH_OP(config->watch)), config->watch);
	else if (config->mode == SYSMON_LOG)
		printf("Observing open/read/write for all processes except the collector.\n");
	if (config->drops)
		fprintf(stderr, "Warning: %llu events have been lost from the kernel queue since the last --off (or module load).\n",
			config->drops);
}
