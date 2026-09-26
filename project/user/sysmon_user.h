/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SYSMON_USER_H
#define SYSMON_USER_H

#include <stdbool.h>
#include <stdio.h>
#include "sysmon.h"

struct sysmon_options {
	int mode;
	int pid;
	int syscall;
	bool collect;
	bool status;
	const char *metrics_path;
	const char *fsm_path;
	bool once;
};

struct sysmon_config {
	int mode;
	int pid;
	int syscall;
	unsigned long long drops;
	unsigned long long watch;
};

#define SYSMON_FSM_MAX_STATES 256
struct sysmon_fsm {
	int states[SYSMON_FSM_MAX_STATES];
	size_t count, current;
	unsigned long long watch, cycles;
	bool once;
};

/*
 * Load and validate the ordered syscall states from a bounded JSON file
 * without changing device settings.
 */
int sysmon_fsm_load(const char *path, struct sysmon_fsm *fsm);

/*
 * Reset FSM progress, arm the first state, verify match delivery is supported,
 * and announce startup.
 */
int sysmon_fsm_start(int fd, FILE *log_file, struct sysmon_fsm *fsm);

/*
 * Check that a record matches the current watch and expected operation of an
 * unfinished FSM.
 */
bool sysmon_fsm_matches(const struct sysmon_fsm *fsm, const struct sysmon_record *record);

/*
 * Advance on a valid match, arming the next state or switching OFF after a
 * single cycle, and announce the transition.
 */
int sysmon_fsm_advance(int fd, FILE *log_file, struct sysmon_fsm *fsm,
		       const struct sysmon_record *record);

/*
 * Verify that the kernel watch still matches the FSM, detecting external
 * configuration changes.
 */
int sysmon_fsm_check(int fd, const struct sysmon_fsm *fsm);

/*
 * Fetch a dedicated match; return one for a valid current match, zero for no
 * usable match, or -1 on error.
 */
int sysmon_fsm_receive(int fd, const struct sysmon_fsm *fsm, struct sysmon_record *record);

/* Return the printable mode name, or "unknown" for an unrecognized value. */
const char *sysmon_mode_name(int mode);

/*
 * Return the printable syscall category, or "unset" for an unrecognized value.
 */
const char *sysmon_op_name(int op);

/* Write command-line usage and supported options to the requested stream. */
void sysmon_usage(FILE *stream, const char *program);

/*
 * Parse and validate CLI options; return zero for success, positive for help,
 * or negative for invalid arguments.
 */
int sysmon_parse_commands(int argc, char **argv, struct sysmon_options *options);

/*
 * Read the current mode, drop count, and mode-specific block rule or FSM
 * watch.
 */
int sysmon_get_config(int fd, struct sysmon_config *config);

/*
 * Apply requested settings in an order that avoids enabling an incomplete
 * block rule.
 */
int sysmon_apply_commands(int fd, const struct sysmon_options *options);

/* Print the active configuration and warn when records have been dropped. */
void sysmon_print_config(const struct sysmon_config *config);

/*
 * Open sysmon.log for append and enable line buffering, returning NULL on
 * failure.
 */
FILE *sysmon_open_log(void);
struct sysmon_metrics;

/*
 * Allocate a bounded measurement buffer and create a new CSV file without
 * overwriting existing data.
 */
struct sysmon_metrics *sysmon_metrics_open(const char *path);

/*
 * Read a monotonic timestamp in nanoseconds, returning -1 if the clock read
 * fails.
 */
int sysmon_metrics_now(unsigned long long *ns);

/*
 * Buffer event identity and capture/receive/append times, counting overflow
 * when the measurement buffer is full.
 */
void sysmon_metrics_record(struct sysmon_metrics *metrics,
			   const struct sysmon_record *record,
			   unsigned long long receive_ns,
			   unsigned long long append_ns);

/*
 * Write buffered measurements to CSV and release resources, reporting output
 * failures or buffer overflow.
 */
int sysmon_metrics_close(struct sysmon_metrics *metrics);

/*
 * Poll and process ordinary event batches or dedicated FSM matches until
 * stopped, reporting delivery and output errors.
 */
int sysmon_collect(int fd, FILE *log_file,
		   struct sysmon_metrics *metrics,
		   struct sysmon_fsm *fsm);

#endif
