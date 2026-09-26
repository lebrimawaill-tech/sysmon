/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include "sysmon.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Each worker performs syscalls in a non-leader thread. Its control channel
 * uses send/recv, so blocking read/write cannot deadlock the test protocol.
 */
enum action { ACTION_OPEN, ACTION_OPENAT, ACTION_OPENAT2, ACTION_READ, ACTION_WRITE };

struct response {
	long result;
	int error;
	int tid;
	unsigned long args[4];
	char data[4];
};

struct worker {
	pid_t pid;
	int socket;
};

struct expected {
	pid_t pid;
	unsigned long long watch;
	enum action action;
	bool blocked;
	bool seen;
	struct response response;
};

static int control_fd = -1;
static int data_fd = -1;
static int initial_pid;
static int initial_op;
static bool restore_config;
static bool fixture_created;
static struct worker workers[2] = { { 0, -1 }, { 0, -1 } };
static char directory[] = "/tmp/sysmon-test-XXXXXX";
static char data_path[256];
static char create_path[256];

/*
 * Restore module settings, stop workers, close test descriptors, and remove
 * temporary fixtures.
 */
static void cleanup(void)
{
	size_t i;

	if (restore_config) {
		(void)ioctl(control_fd, SYSMON_SET_MODE, SYSMON_OFF);
		(void)ioctl(control_fd, SYSMON_SET_PID, initial_pid);
		(void)ioctl(control_fd, SYSMON_SET_SYSCALL, initial_op);
	}
	for (i = 0; i < 2; i++) {
		if (workers[i].pid > 0) {
			(void)kill(workers[i].pid, SIGKILL);
			while (waitpid(workers[i].pid, NULL, 0) < 0 && errno == EINTR)
				;
		}
		if (workers[i].socket >= 0)
			close(workers[i].socket);
	}
	if (control_fd >= 0)
		close(control_fd);
	if (data_fd >= 0)
		close(data_fd);
	if (create_path[0])
		(void)unlink(create_path);
	if (data_path[0])
		(void)unlink(data_path);
	if (fixture_created)
		(void)rmdir(directory);
}

/* Print a formatted test failure and exit through registered cleanup. */
static void fail(const char *format, ...)
{
	va_list ap;

	fprintf(stderr, "FAIL: ");
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

#define REQUIRE(condition, ...) do { \
	if (!(condition)) \
		fail(__VA_ARGS__); \
} while (0)

/*
 * Read nanoseconds from the requested clock, failing the test if the read
 * fails.
 */
static unsigned long long now_ns(clockid_t clock)
{
	struct timespec now;

	REQUIRE(clock_gettime(clock, &now) == 0, "clock_gettime: %s", strerror(errno));
	return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

/* Set a scalar module option, failing the test if the ioctl is rejected. */
static void set_value(unsigned long request, unsigned long value)
{
	REQUIRE(ioctl(control_fd, request, value) == 0,
		"ioctl(%#lx, %lu): %s", request, value, strerror(errno));
}

/* Read an integer module setting, failing the test if the ioctl is rejected. */
static int get_value(unsigned long request)
{
	int value;

	REQUIRE(ioctl(control_fd, request, &value) == 0,
		"ioctl(%#lx): %s", request, strerror(errno));
	return value;
}

/*
 * Execute requested syscalls in a nonleader thread and return results,
 * arguments, and buffer contents to the controller.
 */
static void *worker_thread(void *argument)
{
	int fd = *(int *)argument;
	int ready = (int)syscall(SYS_gettid);
	enum action action;

	if (send(fd, &ready, sizeof(ready), MSG_NOSIGNAL) != sizeof(ready))
		_exit(2);
	while (recv(fd, &action, sizeof(action), 0) == sizeof(action)) {
		char data[4] = "???";
		struct response response = { .tid = ready };
		struct open_how how = { .flags = O_WRONLY | O_CREAT | O_TRUNC, .mode = 0600 };

		errno = 0;
		switch (action) {
		case ACTION_OPEN:
			response.args[0] = (unsigned long)create_path;
			response.args[1] = O_WRONLY | O_CREAT | O_TRUNC;
			response.args[2] = 0600;
			response.result = syscall(SYS_open, response.args[0],
				response.args[1], response.args[2]);
			break;
		case ACTION_OPENAT:
			response.args[0] = (unsigned long)(long)AT_FDCWD;
			response.args[1] = (unsigned long)create_path;
			response.args[2] = O_WRONLY | O_CREAT | O_TRUNC;
			response.args[3] = 0600;
			response.result = syscall(SYS_openat, response.args[0],
				response.args[1], response.args[2], response.args[3]);
			break;
		case ACTION_OPENAT2:
			response.args[0] = (unsigned long)(long)AT_FDCWD;
			response.args[1] = (unsigned long)create_path;
			response.args[2] = (unsigned long)&how;
			response.args[3] = sizeof(how);
			response.result = syscall(SYS_openat2, response.args[0],
				response.args[1], response.args[2], response.args[3]);
			break;
		case ACTION_READ:
			response.args[0] = data_fd;
			response.args[1] = (unsigned long)data;
			response.args[2] = 3;
			response.result = syscall(SYS_read, response.args[0],
				response.args[1], response.args[2]);
			break;
		case ACTION_WRITE:
			memcpy(data, "XYZ", 3);
			response.args[0] = data_fd;
			response.args[1] = (unsigned long)data;
			response.args[2] = 3;
			response.result = syscall(SYS_write, response.args[0],
				response.args[1], response.args[2]);
			break;
		default:
			_exit(2);
		}
		response.error = errno;
		memcpy(response.data, data, sizeof(data));
		if ((action == ACTION_OPEN || action == ACTION_OPENAT || action == ACTION_OPENAT2) &&
		    response.result >= 0)
			close((int)response.result);
		if (send(fd, &response, sizeof(response), MSG_NOSIGNAL) != sizeof(response))
			_exit(2);
	}
	return NULL;
}

/*
 * Create a child with a worker thread and establish a checked command/response
 * socket connection.
 */
static void start_worker(struct worker *worker)
{
	struct timeval timeout = { .tv_sec = 3 };
	int sockets[2], tid;
	pid_t pid;

	REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == 0,
		"socketpair: %s", strerror(errno));
	REQUIRE(setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO,
		&timeout, sizeof(timeout)) == 0, "setsockopt: %s", strerror(errno));
	pid = fork();
	REQUIRE(pid >= 0, "fork: %s", strerror(errno));
	if (!pid) {
		pthread_t thread;
		size_t i;

		close(sockets[0]);
		close(control_fd);
		for (i = 0; i < 2; i++)
			if (workers[i].socket >= 0)
				close(workers[i].socket);
		if (pthread_create(&thread, NULL, worker_thread, &sockets[1]))
			_exit(2);
		(void)pthread_join(thread, NULL);
		_exit(0);
	}
	close(sockets[1]);
	worker->pid = pid;
	worker->socket = sockets[0];
	REQUIRE(recv(worker->socket, &tid, sizeof(tid), 0) == sizeof(tid),
		"worker handshake: %s", strerror(errno));
	REQUIRE(tid != pid && tid > 0, "worker must execute in a non-leader thread");
}

/*
 * Ask a worker to execute one syscall and verify whether it succeeds or is
 * denied with EPERM.
 */
static struct response run_action(struct worker *worker, enum action action,
				  bool blocked)
{
	struct response response;

	REQUIRE(send(worker->socket, &action, sizeof(action), MSG_NOSIGNAL) == sizeof(action),
		"send worker command: %s", strerror(errno));
	REQUIRE(recv(worker->socket, &response, sizeof(response), 0) == sizeof(response),
		"receive worker result (three-second timeout): %s", strerror(errno));
	if (blocked)
		REQUIRE(response.result == -1 && response.error == EPERM,
			"action %d on PID %d expected EPERM; got %ld errno %d",
			action, worker->pid, response.result, response.error);
	else
		REQUIRE(response.result >= 0, "action %d on PID %d failed: errno %d",
			action, worker->pid, response.error);
	return response;
}

/*
 * Restore the fixture contents, length, and file offset before a side-effect
 * check.
 */
static void reset_data(void)
{
	REQUIRE(pwrite(data_fd, "abcdef", 6, 0) == 6, "initialize data: %s", strerror(errno));
	REQUIRE(ftruncate(data_fd, 6) == 0, "truncate test data: %s", strerror(errno));
	REQUIRE(lseek(data_fd, 0, SEEK_SET) == 0, "reset file position: %s", strerror(errno));
}

/*
 * Verify fixture contents and offset to detect unexpected syscall side
 * effects.
 */
static void require_data(const char *expected, off_t offset)
{
	char data[6];

	REQUIRE(pread(data_fd, data, sizeof(data), 0) == sizeof(data), "read test data");
	REQUIRE(memcmp(data, expected, sizeof(data)) == 0,
		"unexpected write side effect in test file");
	REQUIRE(lseek(data_fd, 0, SEEK_CUR) == offset,
		"unexpected file offset (blocked read/write must not advance it)");
}

/*
 * Drain ordinary event batches with a bounded loop and validate record
 * framing.
 */
static void discard_records(void)
{
	struct sysmon_record records[SYSMON_READ_MAX];
	unsigned int batches;
	ssize_t bytes;

	for (batches = 0; batches < 4096; batches++) {
		bytes = read(control_fd, records, sizeof(records));
		if (bytes < 0 && errno == EAGAIN)
			return;
		REQUIRE(bytes > 0 && bytes % sizeof(records[0]) == 0,
			"read records: %s", strerror(errno));
	}
	fail("record queue did not drain with mode OFF");
}

/* Map a test action to the monitored open, read, or write category. */
static int operation(enum action action)
{
	return action == ACTION_READ ? SYSMON_READ :
		action == ACTION_WRITE ? SYSMON_WRITE : SYSMON_OPEN;
}

/* Return the native syscall name corresponding to a test action. */
static const char *syscall_name(enum action action)
{
	static const char *const names[] = { "open", "openat", "openat2", "read", "write" };

	return names[action];
}

/*
 * Match captured records against expected syscall identities, arguments,
 * timestamps, watch tokens, and blocking decisions.
 */
static void check_records(struct expected *expected, size_t count,
			  unsigned long long wall_start,
			  unsigned long long mono_start, bool only_expected)
{
	struct sysmon_record records[SYSMON_READ_MAX];
	unsigned long long wall_end = now_ns(CLOCK_REALTIME);
	unsigned long long mono_end = now_ns(CLOCK_MONOTONIC);
	unsigned int batches;
	size_t i, j;
	ssize_t bytes;

	for (batches = 0; batches < 4096; batches++) {
		bytes = read(control_fd, records, sizeof(records));
		if (bytes < 0 && errno == EAGAIN)
			break;
		REQUIRE(bytes > 0 && bytes % sizeof(records[0]) == 0,
			"read records: %s", strerror(errno));
		for (i = 0; i < (size_t)bytes / sizeof(records[0]); i++) {
			struct sysmon_record *record = &records[i];
			bool matched = false;

			if (record->watch)
				REQUIRE(!record->blocked && record->op == SYSMON_WATCH_OP(record->watch),
					"FSM captured an operation outside its watch");

			REQUIRE(record->pid != getpid(), "collector logged its own syscall");
			for (j = 0; j < count; j++) {
				struct expected *event = &expected[j];
				size_t nargs = event->action == ACTION_OPENAT ||
					event->action == ACTION_OPENAT2 ? 4 : 3;

				if (event->seen || record->pid != event->pid ||
				    strncmp(record->name, syscall_name(event->action),
					    sizeof(record->name)) != 0)
					continue;
				REQUIRE(record->op == operation(event->action), "wrong record operation");
				REQUIRE(record->watch == event->watch, "wrong event watch token");
				REQUIRE(record->tid == event->response.tid, "wrong thread ID in record");
				REQUIRE(!!record->blocked == event->blocked, "wrong blocked status");
				REQUIRE(record->wall_ns >= wall_start && record->wall_ns <= wall_end,
					"capture wall timestamp outside syscall interval");
				REQUIRE(record->mono_ns >= mono_start && record->mono_ns <= mono_end,
					"capture monotonic timestamp outside syscall interval");
				REQUIRE(record->seq > 0, "record sequence must be positive");
				REQUIRE(record->comm[0] != '\0', "missing process name");
				REQUIRE(memcmp(record->args, event->response.args,
					nargs * sizeof(record->args[0])) == 0,
					"arguments differ for %s", syscall_name(event->action));
				if (operation(event->action) == SYSMON_OPEN)
					REQUIRE(strncmp(record->path, create_path, sizeof(record->path)) == 0,
						"open path differs from captured pathname");
				event->seen = true;
				matched = true;
				break;
			}
			if (only_expected)
				REQUIRE(matched, "BLOCK emitted a record for a nonmatching operation/process");
		}
	}
	REQUIRE(batches < 4096, "queue did not drain");
	for (j = 0; j < count; j++)
		REQUIRE(expected[j].seen, "missing %s record for PID %d",
			syscall_name(expected[j].action), expected[j].pid);
}

/*
 * Verify that an empty nonblocking collector returns EAGAIN and has no poll
 * readiness.
 */
static void check_empty(void)
{
	struct sysmon_record record;
	struct pollfd poll_fd = { .fd = control_fd, .events = POLLIN };

	errno = 0;
	REQUIRE(read(control_fd, &record, sizeof(record)) == -1 && errno == EAGAIN,
		"empty nonblocking collector read should return EAGAIN");
	REQUIRE(poll(&poll_fd, 1, 0) == 0, "empty collector should not be readable");
}

/*
 * Check control-request validation, exclusive collector ownership, and empty
 * nonblocking reads and polls.
 */
static void test_ioctls(void)
{
	int other_fd, before;

	before = get_value(SYSMON_GET_MODE);
	errno = 0;
	REQUIRE(ioctl(control_fd, SYSMON_SET_MODE, 99UL) == -1 && errno == EINVAL,
		"invalid mode should return EINVAL");
	REQUIRE(get_value(SYSMON_GET_MODE) == before, "invalid ioctl changed mode");
	before = get_value(SYSMON_GET_SYSCALL);
	errno = 0;
	REQUIRE(ioctl(control_fd, SYSMON_SET_SYSCALL, 99UL) == -1 && errno == EINVAL,
		"invalid operation should return EINVAL");
	REQUIRE(get_value(SYSMON_GET_SYSCALL) == before, "invalid ioctl changed operation");
	before = get_value(SYSMON_GET_PID);
	errno = 0;
	REQUIRE(ioctl(control_fd, SYSMON_SET_PID, (unsigned long)-1) == -1 && errno == EINVAL,
		"negative PID should return EINVAL");
	REQUIRE(get_value(SYSMON_GET_PID) == before, "invalid ioctl changed PID");
	errno = 0;
	REQUIRE(ioctl(control_fd, _IO(SYSMON_MAGIC, 127), 0UL) == -1 && errno == ENOTTY,
		"unknown ioctl should return ENOTTY");
	other_fd = open(SYSMON_DEV, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	REQUIRE(other_fd >= 0, "open second control fd: %s", strerror(errno));
	errno = 0;
	REQUIRE(ioctl(other_fd, SYSMON_EXCLUDE_SELF) == -1 && errno == EBUSY,
		"second collector should return EBUSY");
	close(other_fd);
	set_value(SYSMON_EXCLUDE_SELF, 0);
	discard_records();
	check_empty();
	puts("PASS: ioctl validation, exclusive collector, nonblocking read/poll");
}

/*
 * Verify that OFF permits syscalls and their expected side effects without
 * capturing records.
 */
static void test_off(void)
{
	struct response response;

	set_value(SYSMON_SET_PID, workers[0].pid);
	set_value(SYSMON_SET_SYSCALL, SYSMON_WRITE);
	reset_data();
	response = run_action(&workers[0], ACTION_READ, false);
	REQUIRE(response.result == 3 && memcmp(response.data, "abc", 3) == 0,
		"OFF read failed");
	reset_data();
	response = run_action(&workers[0], ACTION_WRITE, false);
	REQUIRE(response.result == 3, "OFF write failed");
	require_data("XYZdef", 3);
	(void)run_action(&workers[0], ACTION_OPEN, false);
	(void)run_action(&workers[0], ACTION_OPENAT, false);
	(void)run_action(&workers[0], ACTION_OPENAT2, false);
	REQUIRE(access(create_path, F_OK) == 0, "OFF open did not create its file");
	check_empty();
	puts("PASS: OFF allows open/openat/openat2/read/write and creates no records");
}

/*
 * Verify that LOG captures the expected syscalls and exposes queued records
 * through poll.
 */
static void test_log(void)
{
	struct expected events[5] = { 0 };
	struct pollfd poll_fd = { .fd = control_fd, .events = POLLIN };
	unsigned long long wall_start, mono_start;
	size_t i;

	/* Neither parameter may filter LOG records. */
	set_value(SYSMON_SET_PID, workers[1].pid);
	set_value(SYSMON_SET_SYSCALL, SYSMON_WRITE);
	reset_data();
	wall_start = now_ns(CLOCK_REALTIME);
	mono_start = now_ns(CLOCK_MONOTONIC);
	set_value(SYSMON_SET_MODE, SYSMON_LOG);
	for (i = 0; i < 5; i++) {
		events[i].pid = workers[0].pid;
		events[i].action = (enum action)i;
		events[i].response = run_action(&workers[0], (enum action)i, false);
	}
	set_value(SYSMON_SET_MODE, SYSMON_OFF);
	REQUIRE(poll(&poll_fd, 1, 1000) == 1 && (poll_fd.revents & POLLIN),
		"collector poll failed to report captured records");
	check_records(events, 5, wall_start, mono_start, false);
	check_empty();
	puts("PASS: LOG ignores target filters and captures identity, arguments, path and timestamps");
}

/*
 * Verify watch-token isolation and dedicated match delivery, including full-
 * ring and failed-copy cases.
 */
static void test_watch(void)
{
	struct sysmon_record first, again, batch[SYSMON_READ_MAX];
	struct sysmon_stats stats;
	struct sysmon_log_progress before, after;
	struct pollfd descriptor = { .fd = control_fd, .events = POLLPRI };
	unsigned long long watch = SYSMON_READ, next, observed, session_drops, lifetime_drops;
	unsigned int i, drained = 0;
	ssize_t bytes;
	int other_fd;

	REQUIRE(ioctl(control_fd, SYSMON_GET_MATCH, &first) == -1 && errno == EAGAIN,
		"unarmed watch must have no notification");
	set_value(SYSMON_SET_MODE, SYSMON_LOG);
	other_fd = open(SYSMON_DEV, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	REQUIRE(other_fd >= 0, "open other controller");
	errno = 0;
	REQUIRE(ioctl(other_fd, SYSMON_SET_WATCH, &watch) == -1 && errno == EACCES,
		"only the collector may configure an FSM watch");
	REQUIRE(ioctl(other_fd, SYSMON_GET_MATCH, &first) == -1 && errno == EACCES,
		"only the collector may receive FSM notifications");
	close(other_fd);
	watch = 99;
	REQUIRE(ioctl(control_fd, SYSMON_SET_WATCH, &watch) == -1 && errno == EINVAL,
		"invalid watch should fail");
	/* Fill and overflow the ordinary log ring without reading it. */
	for (i = 0; i < 4200; i++)
		(void)run_action(&workers[0], ACTION_WRITE, false);
	REQUIRE(ioctl(control_fd, SYSMON_GET_STATS, &stats) == 0 && stats.drops > 0 &&
		stats.queue_high == 4096, "test must fill and overflow the log ring");
	REQUIRE(ioctl(control_fd, SYSMON_GET_DROPS, &session_drops) == 0 && session_drops > 0,
		"overflow must increase session drops");
	lifetime_drops = stats.drops;
	REQUIRE(ioctl(control_fd, SYSMON_GET_LOG_PROGRESS, &before) == 0, "snapshot ring delivery");
	watch = SYSMON_READ;
	REQUIRE(ioctl(control_fd, SYSMON_SET_WATCH, &watch) == 0, "arm read watch");
	REQUIRE(watch > 255 && SYSMON_WATCH_OP(watch) == SYSMON_READ, "watch token");
	reset_data();
	(void)run_action(&workers[0], ACTION_READ, false);
	REQUIRE(poll(&descriptor, 1, 1000) == 1 && (descriptor.revents & POLLPRI),
		"FSM notification missing while ordinary log ring is full");
	REQUIRE(ioctl(control_fd, SYSMON_GET_MATCH, &first) == 0 && first.watch == watch &&
		first.op == SYSMON_READ && !first.blocked && first.pid != getpid() &&
		first.mono_ns > 0 && first.wall_ns > 0, "invalid match notification");
	REQUIRE(ioctl(control_fd, SYSMON_GET_MATCH, (void *)1) == -1 && errno == EFAULT,
		"invalid copy destination should return EFAULT");
	(void)run_action(&workers[0], ACTION_READ, false);
	(void)run_action(&workers[0], ACTION_WRITE, false);
	(void)run_action(&workers[0], ACTION_OPEN, false);
	REQUIRE(ioctl(control_fd, SYSMON_GET_MATCH, &again) == 0 &&
		!memcmp(&first, &again, sizeof(first)), "pending match was consumed or overwritten");
	REQUIRE(poll(&descriptor, 1, 0) == 1 && (descriptor.revents & POLLPRI),
		"notification readiness must stay asserted until watch changes");
	next = SYSMON_READ;
	REQUIRE(ioctl(control_fd, SYSMON_SET_WATCH, &next) == 0 && next != watch,
		"consecutive same-op watches need distinct tokens");
	REQUIRE(ioctl(control_fd, SYSMON_GET_WATCH, &observed) == 0 && observed == next,
		"get current watch");
	(void)run_action(&workers[0], ACTION_READ, false);
	REQUIRE(poll(&descriptor, 1, 1000) == 1 && (descriptor.revents & POLLPRI),
		"new watch needs its own match");
	REQUIRE(ioctl(control_fd, SYSMON_GET_MATCH, &again) == 0 && again.watch == next &&
		again.seq > first.seq, "stale match satisfied the new watch");
	REQUIRE(ioctl(control_fd, SYSMON_GET_LOG_PROGRESS, &after) == 0 &&
		after.processed_records == before.processed_records,
		"notification reads must not consume normal log records");
	set_value(SYSMON_SET_MODE, SYSMON_OFF);
	REQUIRE(ioctl(control_fd, SYSMON_GET_DROPS, &session_drops) == 0 && session_drops == 0,
		"OFF must reset session drops");
	REQUIRE(ioctl(control_fd, SYSMON_GET_STATS, &stats) == 0 && stats.drops >= lifetime_drops,
		"OFF must preserve lifetime losses for performance accounting");
	lifetime_drops = stats.drops;
	(void)run_action(&workers[0], ACTION_WRITE, false);
	set_value(SYSMON_SET_MODE, SYSMON_OFF);
	REQUIRE(ioctl(control_fd, SYSMON_GET_DROPS, &session_drops) == 0 && session_drops == 0,
		"repeated OFF and disabled syscalls must leave drops zero");
	REQUIRE(ioctl(control_fd, SYSMON_GET_STATS, &stats) == 0 && stats.drops == lifetime_drops,
		"disabled syscalls must not increase lifetime losses");
	REQUIRE(ioctl(control_fd, SYSMON_GET_WATCH, &observed) == 0 && observed == 0,
		"mode changes clear FSM selection");
	REQUIRE(ioctl(control_fd, SYSMON_GET_MATCH, &again) == -1 && errno == EAGAIN,
		"mode change must clear pending matches");
	REQUIRE(poll(&descriptor, 1, 0) == 0, "match readiness remains after clearing watch");
	while ((bytes = read(control_fd, batch, sizeof(batch))) > 0) {
		REQUIRE(bytes % sizeof(batch[0]) == 0, "partial log record");
		for (i = 0; i < bytes / sizeof(batch[0]); i++)
			REQUIRE(batch[i].watch == 0, "FSM notification leaked into ordinary read stream");
		drained += (unsigned int)(bytes / sizeof(batch[0]));
	}
	REQUIRE(bytes == -1 && errno == EAGAIN && drained >= 4096,
		"ordinary log ring was drained or modified by match delivery");
	watch = SYSMON_READ;
	REQUIRE(ioctl(control_fd, SYSMON_SET_WATCH, &watch) == -1 && errno == EINVAL,
		"watch requires LOG mode");
	puts("PASS: independent FSM notifications survive full log ring, repeated reads and failed copies");
	puts("PASS: OFF resets session drops, preserves lifetime losses and leaves queued events readable");
}

/*
 * Verify PID/operation-specific blocking and the absence of side effects for
 * denied syscalls.
 */
static void test_block(enum action action)
{
	struct expected event = { .pid = workers[0].pid, .action = action, .blocked = true };
	unsigned long long wall_start, mono_start;
	struct response response;
	int op = operation(action);

	reset_data();
	(void)unlink(create_path);
	set_value(SYSMON_SET_PID, workers[0].pid);
	set_value(SYSMON_SET_SYSCALL, op);
	wall_start = now_ns(CLOCK_REALTIME);
	mono_start = now_ns(CLOCK_MONOTONIC);
	set_value(SYSMON_SET_MODE, SYSMON_BLOCK);
	event.response = run_action(&workers[0], action, true);
	if (op == SYSMON_OPEN)
		REQUIRE(access(create_path, F_OK) == -1 && errno == ENOENT,
			"blocked open created a file");
	else {
		require_data("abcdef", 0);
		if (op == SYSMON_READ)
			REQUIRE(memcmp(event.response.data, "???", 3) == 0,
				"blocked read modified userspace memory");
	}
	/* Same operation from another process is allowed. */
	response = run_action(&workers[1], action, false);
	if (op == SYSMON_READ)
		REQUIRE(response.result == 3 && memcmp(response.data, "abc", 3) == 0,
			"blocked read consumed data before the next reader");
	if (op == SYSMON_WRITE)
		require_data("XYZdef", 3);
	/* Other operations in the selected process are also allowed. */
	reset_data();
	if (op != SYSMON_READ)
		(void)run_action(&workers[0], ACTION_READ, false);
	if (op != SYSMON_WRITE)
		(void)run_action(&workers[0], ACTION_WRITE, false);
	if (op != SYSMON_OPEN)
		(void)run_action(&workers[0], ACTION_OPEN, false);
	set_value(SYSMON_SET_MODE, SYSMON_OFF);
	check_records(&event, 1, wall_start, mono_start, true);
	check_empty();
	printf("PASS: BLOCK %s matches TGID/operation, prevents side effects and records denial\n",
		syscall_name(action));
}

/*
 * Check live-module prerequisites and run ioctl, OFF, LOG, watch, and BLOCK
 * integration tests.
 */
int main(void)
{
	int mode;

	control_fd = open(SYSMON_DEV, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (control_fd < 0) {
		fprintf(stderr, "FAIL: cannot open %s: %s (load sysmon and run as root)\n",
			SYSMON_DEV, strerror(errno));
		return EXIT_FAILURE;
	}
	atexit(cleanup);
	mode = get_value(SYSMON_GET_MODE);
	if (mode != SYSMON_OFF) {
		fprintf(stderr, "FAIL: module must initially be OFF; active policy left unchanged\n");
		return EXIT_FAILURE;
	}
	initial_pid = get_value(SYSMON_GET_PID);
	initial_op = get_value(SYSMON_GET_SYSCALL);
	if (ioctl(control_fd, SYSMON_EXCLUDE_SELF) < 0 && errno == EBUSY) {
		fprintf(stderr, "FAIL: another collector is active\n");
		return EXIT_FAILURE;
	}
	REQUIRE(ioctl(control_fd, SYSMON_EXCLUDE_SELF) == 0,
		"claim collector: %s", strerror(errno));
	restore_config = true;
	REQUIRE(mkdtemp(directory) != NULL, "mkdtemp: %s", strerror(errno));
	fixture_created = true;
	snprintf(data_path, sizeof(data_path), "%s/data", directory);
	snprintf(create_path, sizeof(create_path), "%s/created", directory);
	data_fd = open(data_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	REQUIRE(data_fd >= 0, "create test data: %s", strerror(errno));
	start_worker(&workers[0]);
	start_worker(&workers[1]);
	test_ioctls();
	test_off();
	test_log();
	test_watch();
	test_log(); /* Ordinary LOG must capture all operations again after FSM use. */
	test_block(ACTION_OPEN);
	test_block(ACTION_OPENAT);
	test_block(ACTION_OPENAT2);
	test_block(ACTION_READ);
	test_block(ACTION_WRITE);
	puts("All sysmon integration checks passed.");
	return 0;
}
