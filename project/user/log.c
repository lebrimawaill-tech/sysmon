/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "sysmon_user.h"

static volatile sig_atomic_t stop_collecting;

/* Request a clean collector shutdown by setting the signal-safe stop flag. */
static void stop_handler(int signal_number)
{
	(void)signal_number;
	stop_collecting = 1;
}

/*
 * Open sysmon.log for append and enable line buffering, returning NULL on
 * failure.
 */
FILE *sysmon_open_log(void)
{
	FILE *file;
	int fd = open("sysmon.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);

	if (fd < 0) {
		fprintf(stderr, "Cannot open ./sysmon.log: %s\n", strerror(errno));
		return NULL;
	}
	file = fdopen(fd, "a");
	if (!file) {
		int saved_errno = errno;

		close(fd);
		fprintf(stderr, "Cannot open log stream: %s\n", strerror(saved_errno));
		return NULL;
	}
	/* Each complete line is appended immediately instead of waiting for a batch. */
	if (setvbuf(file, NULL, _IOLBF, 0)) {
		fprintf(stderr, "Cannot configure the log stream.\n");
		fclose(file);
		return NULL;
	}
	return file;
}

/*
 * Escape untrusted text into a bounded buffer so control characters and quotes
 * cannot break a log field.
 */
static void escape_text(char *out, size_t capacity, const char *input, size_t length)
{
	static const char hex[] = "0123456789abcdef";
	size_t used = 0, index;

	for (index = 0; index < length && input[index]; ++index) {
		unsigned char value = (unsigned char)input[index];

		if (value >= 0x20 && value <= 0x7e && value != '"' && value != '\\') {
			if (used + 1 >= capacity)
				break;
			out[used++] = (char)value;
		} else if (value == '"' || value == '\\') {
			if (used + 2 >= capacity)
				break;
			out[used++] = '\\';
			out[used++] = (char)value;
		} else {
			if (used + 4 >= capacity)
				break;
			out[used++] = '\\';
			out[used++] = 'x';
			out[used++] = hex[value >> 4];
			out[used++] = hex[value & 0xf];
		}
	}
	out[used] = '\0';
}

struct timestamp_cache {
	time_t seconds;
	char date[32];
	bool valid;
};

struct log_timestamps {
	struct timestamp_cache captured;
	struct timestamp_cache appended;
};

/*
 * Format UTC nanoseconds using a cached whole-second prefix; return -1 on
 * conversion failure or truncation.
 */
static int timestamp(char *out, size_t capacity, unsigned long long ns,
		     struct timestamp_cache *cache)
{
	time_t seconds = (time_t)(ns / 1000000000ULL);
	int length;

	/* Equality also handles out-of-order captures and backward clock steps.
	 * Keep capture and append caches separate when draining older events. */
	if (!cache->valid || cache->seconds != seconds) {
		struct tm utc;

		cache->valid = false;
		if (!gmtime_r(&seconds, &utc) ||
		    !strftime(cache->date, sizeof(cache->date), "%Y-%m-%dT%H:%M:%S", &utc))
			return -1;
		cache->seconds = seconds;
		cache->valid = true;
	}
	length = snprintf(out, capacity, "%s.%09lluZ", cache->date, ns % 1000000000ULL);
	return length < 0 || (size_t)length >= capacity ? -1 : 0;
}

/*
 * Format and flush one event to the log, record optional completion metrics,
 * and print its console summary.
 */
static int append_record(FILE *file, const struct sysmon_record *record,
			 struct sysmon_metrics *metrics, unsigned long long receive_ns,
			 struct log_timestamps *timestamps)
{
	char comm[SYSMON_COMM_LEN * 4 + 1];
	char name[SYSMON_NAME_LEN * 4 + 1];
	char path[SYSMON_PATH_LEN * 4 + 1];
	char details[192];
	char captured[48], appended[48];
	struct timespec now;
	unsigned long long append_ns;
	/* Apply color from the event, including records queued before a mode change. */
	const char *color = record->blocked ? "\033[31m" : "";
	const char *reset = record->blocked ? "\033[0m" : "";

	escape_text(comm, sizeof(comm), record->comm, sizeof(record->comm));
	escape_text(name, sizeof(name), record->name, sizeof(record->name));
	escape_text(path, sizeof(path), record->path, sizeof(record->path));
	if (record->op == SYSMON_READ || record->op == SYSMON_WRITE)
		snprintf(details, sizeof(details), "fd=%d buffer=0x%lx count=%lu",
			 (int)record->args[0], record->args[1], record->args[2]);
	else if (!strcmp(name, "openat"))
		snprintf(details, sizeof(details), "dirfd=%d pathname=0x%lx flags=0x%lx mode=0%lo",
			 (int)record->args[0], record->args[1], record->args[2], record->args[3]);
	else if (!strcmp(name, "openat2"))
		snprintf(details, sizeof(details), "dirfd=%d pathname=0x%lx how=0x%lx size=%lu",
			 (int)record->args[0], record->args[1], record->args[2], record->args[3]);
	else if (!strcmp(name, "open"))
		snprintf(details, sizeof(details), "pathname=0x%lx flags=0x%lx mode=0%lo",
			 record->args[0], record->args[1], record->args[2]);
	else
		details[0] = '\0';
	if (clock_gettime(CLOCK_REALTIME, &now) < 0) {
		fprintf(stderr, "Cannot get append time: %s\n", strerror(errno));
		return -1;
	}
	append_ns = (unsigned long long)now.tv_sec * 1000000000ULL +
		    (unsigned long long)now.tv_nsec;
	if (timestamp(captured, sizeof(captured), record->wall_ns, &timestamps->captured) ||
	    timestamp(appended, sizeof(appended), append_ns, &timestamps->appended)) {
		fprintf(stderr, "Cannot format event timestamps.\n");
		return -1;
	}
	/* Appended time is sampled immediately before the line's append. It does
	 * not claim a disk-durability timestamp; no fsync is done per syscall. */
	if (fprintf(file,
		    "%scaptured=%s appended=%s capture_ns=%llu append_ns=%llu "
		    "mono_ns=%llu seq=%llu pid=%d tid=%d comm=\"%s\" "
		    "syscall=\"%s\" operation=%s blocked=%s "
		    "args=[0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx] "
		    "%s path=\"%s\" source=%s watch=%llu%s\n\n",
		    color, captured, appended, record->wall_ns, append_ns, record->mono_ns,
		    record->seq, record->pid, record->tid, comm, name,
		    sysmon_op_name(record->op), record->blocked ? "yes" : "no",
		    record->args[0], record->args[1], record->args[2],
		    record->args[3], record->args[4], record->args[5], details, path,
		    record->watch ? "fsm_match" : "log_ring", record->watch,
		    reset) < 0 || fflush(file)) {
		fprintf(stderr, "Cannot append to sysmon.log: %s\n", strerror(errno));
		return -1;
	}
	if (metrics) {
		unsigned long long completed_ns;

		/* This is completion in the filesystem page cache, not fsync durability. */
		if (sysmon_metrics_now(&completed_ns))
			return -1;
		sysmon_metrics_record(metrics, record, receive_ns, completed_ns);
	}
	if (printf("%sObserved syscall=%s pid=%d tid=%d comm=\"%s\" blocked=%s captured=%s%s\n\n",
		    color, name, record->pid, record->tid, comm,
		    record->blocked ? "yes" : "no", captured, reset) < 0 || fflush(stdout)) {
		fprintf(stderr, "Cannot write console output: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Poll and process ordinary event batches or dedicated FSM matches until
 * stopped, reporting delivery and output errors.
 */
int sysmon_collect(int fd, FILE *log_file,
		   struct sysmon_metrics *metrics,
		   struct sysmon_fsm *fsm)
{
	unsigned char buffer[sizeof(struct sysmon_record) * SYSMON_READ_MAX];
	struct log_timestamps timestamps = { 0 };
	struct sigaction action = { .sa_handler = stop_handler };
	struct sigaction old_int, old_term;
	struct pollfd descriptor = { .fd = fd, .events = fsm ? POLLPRI : POLLIN };
	struct sysmon_stats stats;
	unsigned long long records = 0, initial_drops = 0;
	size_t pending = 0;
	int result = -1;

	/* Measure only this collection interval when metrics are requested.
	 * Lifetime totals preserve losses across another CLI's OFF/reset. */
	if (metrics) {
		if (ioctl(fd, SYSMON_GET_STATS, &stats) < 0) {
			fprintf(stderr, "Cannot get initial drop count: %s\n", strerror(errno));
			return -1;
		}
		initial_drops = stats.drops;
	}
	stop_collecting = 0;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, &old_int) < 0) {
		fprintf(stderr, "Cannot install SIGINT handler: %s\n", strerror(errno));
		return -1;
	}
	if (sigaction(SIGTERM, &action, &old_term) < 0) {
		fprintf(stderr, "Cannot install SIGTERM handler: %s\n", strerror(errno));
		sigaction(SIGINT, &old_int, NULL);
		return -1;
	}
	while (!stop_collecting) {
		/* Bound the wait if a stop signal arrives between the loop condition
		 * and poll(), before there is a blocking syscall to interrupt. */
		int ready = poll(&descriptor, 1, 250);

		if (ready < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "Cannot wait for events: %s\n", strerror(errno));
			goto out;
		}
		if (fsm && sysmon_fsm_check(fd, fsm))
			goto out;
		if (ready == 0)
			continue;
		if (descriptor.revents & POLLNVAL) {
			fprintf(stderr, "Event device is no longer valid.\n");
			goto out;
		}
		if (!(descriptor.revents & descriptor.events)) {
			if (descriptor.revents & (POLLERR | POLLHUP)) {
				fprintf(stderr, "Event device stopped providing records.\n");
				goto out;
			}
			continue;
		}
		if (fsm) {
			struct sysmon_record record;
			unsigned long long receive_ns = 0;
			int matched = sysmon_fsm_receive(fd, fsm, &record);

			if (matched < 0)
				goto out;
			if (!matched)
				continue;
			if (metrics && sysmon_metrics_now(&receive_ns))
				goto out;
			/* The dedicated match is held until advancing the watch. The
			 * ordinary read() stream and its drop count cannot drive the FSM.
			 */
			if (append_record(log_file, &record, metrics, receive_ns, &timestamps))
				goto out;
			++records;
			if (sysmon_fsm_advance(fd, log_file, fsm, &record))
				goto out;
			if (fsm->once && fsm->cycles)
				goto completed;
			continue;
		}
		while (!stop_collecting) {
			ssize_t received = read(fd, buffer + pending, sizeof(buffer) - pending);
			unsigned long long receive_ns = 0;
			size_t available, offset;

			/* One timestamp for the completed read batch; no added clock calls
			 * or metric storage when --metrics was not requested. */
			if (metrics && received > 0 && sysmon_metrics_now(&receive_ns))
				goto out;
			if (received < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				if (errno == EINTR)
					continue;
				fprintf(stderr, "Cannot read events: %s\n", strerror(errno));
				goto out;
			}
			if (received == 0) {
				fprintf(stderr, "Event stream ended%s.\n",
					pending ? " during a record" : "");
				goto out;
			}
			available = pending + (size_t)received;
			for (offset = 0; available - offset >= sizeof(struct sysmon_record);
			     offset += sizeof(struct sysmon_record)) {
				struct sysmon_record record;

				memcpy(&record, buffer + offset, sizeof(record));
				if (append_record(log_file, &record, metrics, receive_ns, &timestamps))
					goto out;
				++records;
			}
			pending = available - offset;
			memmove(buffer, buffer + offset, pending);
		}
	}
completed:
	result = 0;
out:
	if (pending)
		fprintf(stderr, "Discarding %zu bytes of an incomplete record.\n", pending);
	if (!metrics) {
		printf("Collection stopped: %llu records appended.\n", records);
	} else if (ioctl(fd, SYSMON_GET_STATS, &stats) < 0) {
		fprintf(stderr, "Cannot get final drop count: %s\n", strerror(errno));
		result = -1;
	} else {
		unsigned long long lost = stats.drops - initial_drops;

		printf("Collection stopped: %llu records appended; %llu queue drops during collection.\n",
		       records, lost);
		if (lost)
			fprintf(stderr, "Warning: the kernel queue lost %llu events during collection.\n", lost);
	}
	if (fsm && fsm->once && fsm->cycles)
		printf("FSM completed one cycle and returned to state 1; current mode: off.\n");
	else
		printf("The module's mode is unchanged by stopping collection; use --off to disable it.\n");
	if (fsm && !(fsm->once && fsm->cycles))
		printf("Closing the FSM collector clears its watch; log mode then observes all operations.\n");
	sigaction(SIGTERM, &old_term, NULL);
	sigaction(SIGINT, &old_int, NULL);
	return result;
}
