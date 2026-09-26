/* SPDX-License-Identifier: GPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../user/sysmon_user.h"

/* Exercise the real collector and formatter without a privileged module.
 * The ordinary stream is forbidden; only explicit match notifications exist.
 */
static struct sysmon_fsm *active;
static unsigned long long watch, generation;
static unsigned int delivered, polls, off_calls, empty_replies, stats_calls;
static bool receive_error;

/*
 * Simulate match delivery and control requests, including dropped ordinary
 * events, empty replies, and receive errors.
 */
int __wrap_ioctl(int fd, unsigned long command, ...)
{
	va_list ap;
	unsigned long long *value;

	(void)fd;
	va_start(ap, command);
	switch (command) {
	case SYSMON_GET_MODE:
		*va_arg(ap, int *) = SYSMON_OFF;
		break;
	case SYSMON_SET_MODE:
		assert(va_arg(ap, unsigned long) == SYSMON_OFF);
		off_calls++;
		watch = 0;
		break;
	case SYSMON_SET_WATCH:
		value = va_arg(ap, unsigned long long *);
		watch = (++generation << 8) | *value;
		*value = watch;
		break;
	case SYSMON_GET_WATCH:
		*va_arg(ap, unsigned long long *) = watch;
		break;
	case SYSMON_GET_STATS:
		/* Historical loss is excluded; lifetime totals survive automatic OFF. */
		*va_arg(ap, struct sysmon_stats *) = (struct sysmon_stats) {
			.drops = 895896 + (polls ? 37 : 0)
		};
		stats_calls++;
		break;
	case SYSMON_GET_MATCH: {
		struct sysmon_record *record = va_arg(ap, struct sysmon_record *);

		va_end(ap);
		if (receive_error) {
			errno = EIO;
			return -1;
		}
		if (empty_replies) {
			empty_replies--;
			errno = EAGAIN;
			return -1;
		}
		assert(active->current == delivered && active->watch == watch);
		*record = (struct sysmon_record) {
			.wall_ns = 1000000000ULL, .mono_ns = 1, .seq = delivered + 1,
			.pid = 42, .tid = 42, .op = active->states[delivered],
			.dropped = 10000, .watch = watch, .comm = "worker"
		};
		snprintf(record->name, sizeof(record->name), "%s", sysmon_op_name(record->op));
		delivered++;
		return 0;
	}
	default: assert(!"unexpected ioctl");
	}
	va_end(ap);
	return 0;
}

/*
 * Simulate ordinary and priority readiness to verify that only dedicated match
 * notifications advance the FSM.
 */
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
	assert(count == 1 && timeout > 0 && fds[0].events == POLLPRI);
	assert(++polls < 20);
	/* Ordinary POLLIN cannot trigger a state transition, even with queued data. */
	fds[0].revents = polls == 1 ? POLLIN : POLLPRI;
	return 1;
}

/* Fail if FSM collection tries to read the ordinary event ring. */
ssize_t __wrap_read(int fd, void *buffer, size_t length)
{
	(void)fd;
	(void)buffer;
	(void)length;
	assert(!"FSM collector must never read the ordinary event stream");
	return -1;
}

/*
 * Validate fortified poll buffer bounds and forward the call to the simulated
 * poll implementation.
 *
 * Fortified libc calls can remain explicit with sanitizer instrumentation.
 */
int __wrap___poll_chk(struct pollfd *fds, nfds_t count, int timeout, size_t size)
{
	assert(count <= size / sizeof(*fds));
	return __wrap_poll(fds, count, timeout);
}

/*
 * Validate fortified read buffer bounds and forward the call to the ordinary-
 * read rejection stub.
 */
ssize_t __wrap___read_chk(int fd, void *buffer, size_t length, size_t size)
{
	assert(length <= size);
	return __wrap_read(fd, buffer, length);
}

/*
 * Exercise the real FSM collector with simulated notifications, checking
 * transitions, output, drop reporting, and receive-error handling.
 */
int main(void)
{
	struct sysmon_fsm fsm = {
		.states = { SYSMON_READ, SYSMON_WRITE, SYSMON_READ, SYSMON_READ },
		.count = 4, .once = true
	};
	char line[2048];
	char output[16384], directory[] = "/tmp/sysmon-measurement-test-XXXXXX";
	char metrics_path[256];
	struct sysmon_metrics *metrics;
	struct sysmon_config config;
	struct sysmon_options options = {
		.mode = SYSMON_OFF, .pid = -1, .syscall = -1
	};
	unsigned int observations = 0, transitions = 0;
	FILE *log = tmpfile();
	FILE *console = tmpfile();
	int saved_stdout;
	size_t length;

	assert(log && console);
	assert(fflush(stdout) == 0);
	saved_stdout = dup(STDOUT_FILENO);
	assert(saved_stdout >= 0 && dup2(fileno(console), STDOUT_FILENO) >= 0);
	active = &fsm;
	/* Startup ABI check and one ready-then-EAGAIN notification race. */
	empty_replies = 2;
	assert(sysmon_fsm_start(7, log, &fsm) == 0);
	assert(sysmon_collect(7, log, NULL, &fsm) == 0);
	assert(delivered == 4 && off_calls == 1 && fsm.cycles == 1 && fsm.current == 0);
	assert(stats_calls == 0);
	rewind(log);
	while (fgets(line, sizeof(line), log)) {
		assert(!strstr(line, "dropped="));
		if (strstr(line, "source=fsm_match"))
			observations++;
		if (strstr(line, "FSM transition")) {
			assert(!strncmp(line, "\033[36m", 5));
			transitions++;
		}
	}
	assert(observations == 4 && transitions == 4);
	fclose(log);
	/* A failed notification fetch must neither fabricate an event nor advance. */
	log = tmpfile();
	assert(log);
	delivered = polls = off_calls = 0;
	empty_replies = 1;
	assert(sysmon_fsm_start(7, log, &fsm) == 0);
	receive_error = true;
	assert(sysmon_collect(7, log, NULL, &fsm) == -1);
	assert(delivered == 0 && off_calls == 0 && fsm.cycles == 0 && fsm.current == 0);
	assert(stats_calls == 0);
	fclose(log);
	/* OFF/status must never request or display historical drop counts. */
	assert(sysmon_apply_commands(7, &options) == 0);
	assert(sysmon_get_config(7, &config) == 0);
	sysmon_print_config(&config);
	assert(fflush(stdout) == 0);
	rewind(console);
	length = fread(output, 1, sizeof(output) - 1, console);
	output[length] = '\0';
	assert(!strstr(output, "drop") && !strstr(output, "Dropped"));
	assert(strstr(output, "Current mode: off\n"));
	assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	fclose(console);

	/* A measured collection reports only 37 new losses, even across OFF. */
	console = tmpfile();
	log = tmpfile();
	assert(console && log && mkdtemp(directory));
	snprintf(metrics_path, sizeof(metrics_path), "%s/metrics.csv", directory);
	metrics = sysmon_metrics_open(metrics_path);
	assert(metrics);
	delivered = polls = off_calls = 0;
	empty_replies = 1;
	receive_error = false;
	assert(dup2(fileno(console), STDOUT_FILENO) >= 0);
	assert(sysmon_fsm_start(7, log, &fsm) == 0);
	assert(sysmon_collect(7, log, metrics, &fsm) == 0);
	assert(stats_calls == 2 && off_calls == 1);
	assert(sysmon_metrics_close(metrics) == 0);
	assert(fflush(stdout) == 0);
	rewind(console);
	length = fread(output, 1, sizeof(output) - 1, console);
	output[length] = '\0';
	assert(strstr(output, "37 queue drops during collection."));
	assert(!strstr(output, "895896") && !strstr(output, "895933"));
	assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);
	fclose(console);
	fclose(log);
	assert(unlink(metrics_path) == 0 && rmdir(directory) == 0);
	puts("PASS: FSM uses only match notifications; ordinary ring readiness/drops cannot advance it");
	puts("PASS: drops are reported only with metrics and exclude losses before measurement");
	return 0;
}
