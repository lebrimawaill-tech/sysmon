// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "sysmon.h"
#include "perf_common.h"

struct worker_result {
	uint64_t start, end, attempts, denied, allowed, errors, side_effects;
};
static int device = -1;
static pid_t worker_pid = -1;
static int old_pid, old_op;
static bool restore;
static volatile sig_atomic_t interrupted;

/* Set the signal-safe flag that tells the blocking test to stop. */
static void stop(int signal_number)
{
	(void)signal_number;
	interrupted = 1;
}

/*
 * Switch the module OFF, restore saved rule settings, terminate the worker,
 * and close the device.
 */
static void cleanup(void)
{
	if (restore) {
		(void)ioctl(device, SYSMON_SET_MODE, SYSMON_OFF);
		(void)ioctl(device, SYSMON_SET_PID, (unsigned long)old_pid);
		(void)ioctl(device, SYSMON_SET_SYSCALL, (unsigned long)old_op);
	}
	if (worker_pid > 0) {
		(void)kill(worker_pid, SIGKILL);
		while (waitpid(worker_pid, NULL, 0) < 0 && errno == EINTR) {}
	}
	if (device >= 0) close(device);
}

/*
 * Report a blocking-test failure with its errno message and exit through
 * registered cleanup.
 */
static void fail(const char *message)
{
	fprintf(stderr, "Blocking test: %s: %s\n", message, strerror(errno));
	exit(EXIT_FAILURE);
}

/* Issue a scalar device setting and fail the test if the ioctl is rejected. */
static void set(unsigned long command, unsigned long value)
{
	if (ioctl(device, command, value)) fail("ioctl");
}

/*
 * Run paced syscall attempts in the child and report denials, errors, and
 * read-buffer side effects to the parent.
 */
static void child_run(int socket, int fd, const struct perf_options *options, int operation)
{
	struct perf_pacer pacer;
	struct worker_result result = { 0 };
	char go, bytes[64];
	close(device);
	if (recv(socket, &go, 1, 0) != 1) _exit(2);
	perf_pacer_init(&pacer, options, 1);
	while (result.attempts < options->max_transactions && perf_wait(&pacer)) {
		long rc;
		memset(bytes, 'Z', sizeof(bytes));
		errno = 0;
		if (operation == SYSMON_OPEN)
			rc = syscall(SYS_open, options->fixture, O_WRONLY | O_TRUNC, 0);
		else if (operation == SYSMON_READ)
			rc = syscall(SYS_read, fd, bytes, sizeof(bytes));
		else
			rc = syscall(SYS_write, fd, bytes, sizeof(bytes));
		result.attempts++;
		if (rc == -1 && errno == EPERM) result.denied++;
		else if (rc >= 0) result.allowed++;
		else result.errors++;
		if (operation == SYSMON_OPEN && rc >= 0) close((int)rc);
		if (operation == SYSMON_READ) {
			for (size_t i = 0; i < sizeof(bytes); i++)
				if (bytes[i] != 'Z') { result.side_effects++; break; }
		}
	}
	result.start = pacer.start;
	result.end = perf_now();
	if (send(socket, &result, sizeof(result), MSG_NOSIGNAL) != sizeof(result)) _exit(2);
	_exit(0);
}

/*
 * Read one event batch, count matching blocked records, and flag unexpected
 * records.
 */
static uint64_t drain(int op, uint64_t *bad_records)
{
	struct sysmon_record batch[SYSMON_READ_MAX];
	uint64_t count = 0;
	/* One bounded batch each call keeps IPC responsive under heavy load. */
	ssize_t n = read(device, batch, sizeof(batch));
	if (n < 0) {
		if (errno != EAGAIN && errno != EINTR) fail("read events");
		return 0;
	}
	if (!n || n % sizeof(batch[0])) { errno = EPROTO; fail("event framing"); }
	for (size_t i = 0; i < (size_t)n / sizeof(batch[0]); i++) {
		if (batch[i].pid == worker_pid && batch[i].op == op && batch[i].blocked)
			count++;
		else
			(*bad_records)++;
	}
	return count;
}

/*
 * Run a controlled blocking workload, verify denial side effects and event
 * accounting, and print the measured results.
 */
int main(int argc, char **argv)
{
	struct perf_options options;
	struct worker_result result;
	struct sysmon_record discard[SYSMON_READ_MAX];
	struct sysmon_stats stats;
	struct stat before, after;
	char initial[64], final[64];
	uint64_t deadline, records = 0, bad_records = 0;
	unsigned long long drops_before, drops_after;
	int fd, sockets[2], mode, operation, status;
	bool done = false;
	if (argc == 2 && !strcmp(argv[1], "--header")) {
		puts("operation,trial,requested_rate,achieved_rate,attempts,denied,allowed,errors,blocked_records,queue_drops,side_effects,elapsed_ns");
		return 0;
	}
	perf_parse(argc, argv, &options);
	operation = !strcmp(options.operation, "open") ? SYSMON_OPEN :
		    !strcmp(options.operation, "read") ? SYSMON_READ : SYSMON_WRITE;
	device = open(SYSMON_DEV, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (device < 0) fail("open /dev/sysmon (load the module and run as root)");
	atexit(cleanup);
	struct sigaction action = { .sa_handler = stop };
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) fail("signals");
	if (ioctl(device, SYSMON_GET_MODE, &mode) || mode != SYSMON_OFF) {
		errno = EBUSY; fail("requires off mode");
	}
	if (ioctl(device, SYSMON_GET_PID, &old_pid) || ioctl(device, SYSMON_GET_SYSCALL, &old_op))
		fail("get configuration");
	set(SYSMON_EXCLUDE_SELF, 0);
	restore = true;
	while (read(device, discard, sizeof(discard)) > 0) {}
	if (errno != EAGAIN) fail("clear old events");
	fd = open(options.fixture, O_RDWR | O_CLOEXEC);
	if (fd < 0 || pread(fd, initial, 64, 0) != 64 || fstat(fd, &before)) fail("fixture");
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets)) fail("socketpair");
	if (ioctl(device, SYSMON_GET_STATS, &stats)) fail("drop count");
	drops_before = stats.drops;
	worker_pid = fork();
	if (worker_pid < 0) fail("fork");
	if (!worker_pid) { close(sockets[0]); child_run(sockets[1], fd, &options, operation); }
	close(sockets[1]);
	set(SYSMON_SET_PID, (unsigned long)worker_pid);
	set(SYSMON_SET_SYSCALL, operation);
	set(SYSMON_SET_MODE, SYSMON_BLOCK);
	if (send(sockets[0], "x", 1, MSG_NOSIGNAL) != 1) fail("start child");
	deadline = perf_now() + options.duration_ms * 1000000ULL + 5000000000ULL;
	while (!done && !interrupted && perf_now() < deadline) {
		struct pollfd descriptors[] = { { device, POLLIN, 0 }, { sockets[0], POLLIN, 0 } };
		int ready = poll(descriptors, 2, 100);
		if (ready < 0 && errno != EINTR) fail("poll");
		if (descriptors[0].revents & POLLIN) records += drain(operation, &bad_records);
		if (descriptors[1].revents & (POLLIN | POLLHUP)) {
			if (recv(sockets[0], &result, sizeof(result), MSG_DONTWAIT) != sizeof(result))
				fail("worker result");
			done = true;
		}
	}
	if (!done) { errno = ETIMEDOUT; fail("worker timeout"); }
	set(SYSMON_SET_MODE, SYSMON_OFF);
	for (unsigned int i = 0; i < 4096; i++) {
		uint64_t n = drain(operation, &bad_records);
		records += n;
		if (!n) break;
	}
	if (ioctl(device, SYSMON_GET_STATS, &stats)) fail("drop count");
	drops_after = stats.drops;
	if (pread(fd, final, 64, 0) != 64 || memcmp(initial, final, 64) ||
	    fstat(fd, &after) || after.st_size != before.st_size || lseek(fd, 0, SEEK_CUR) != 0)
		result.side_effects++;
	if (waitpid(worker_pid, &status, 0) < 0) fail("waitpid");
	worker_pid = -1;
	if (!WIFEXITED(status) || WEXITSTATUS(status)) result.errors++;
	result.errors += bad_records;
	uint64_t elapsed = result.end - result.start;
	printf("%s,%lu,%lu,%.3f,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
	       ",%" PRIu64 ",%llu,%" PRIu64 ",%" PRIu64 "\n", options.operation,
	       options.trial, options.rate, 1e9 * result.attempts / elapsed,
	       result.attempts, result.denied, result.allowed, result.errors,
	       records, drops_after - drops_before, result.side_effects, elapsed);
	close(fd);
	close(sockets[0]);
	return !result.attempts || result.denied != result.attempts || result.errors ||
	       result.side_effects || records + drops_after - drops_before != result.denied;
}
