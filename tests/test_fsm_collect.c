/* SPDX-License-Identifier: GPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
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
	case SYSMON_GET_DROPS:
		/* Old ordinary events were dropped; FSM delivery is independent. */
		*va_arg(ap, unsigned long long *) = off_calls ? 0 : 10000;
		break;
	case SYSMON_GET_STATS:
		/* The final lifetime total survives the FSM's automatic OFF. */
		*va_arg(ap, struct sysmon_stats *) = (struct sysmon_stats) {
			.drops = polls ? 10000 : 0
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
	unsigned int observations = 0, transitions = 0;
	FILE *log = tmpfile();

	assert(log);
	active = &fsm;
	/* Startup ABI check and one ready-then-EAGAIN notification race. */
	empty_replies = 2;
	assert(sysmon_fsm_start(7, log, &fsm) == 0);
	assert(sysmon_collect(7, log, NULL, &fsm) == 0);
	assert(delivered == 4 && off_calls == 1 && fsm.cycles == 1 && fsm.current == 0);
	assert(stats_calls == 2);
	rewind(log);
	while (fgets(line, sizeof(line), log)) {
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
	assert(stats_calls == 4);
	fclose(log);
	puts("PASS: FSM uses only match notifications; ordinary ring readiness/drops cannot advance it");
	return 0;
}
