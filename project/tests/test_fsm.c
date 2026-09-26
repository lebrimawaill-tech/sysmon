/* SPDX-License-Identifier: GPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../user/sysmon_user.h"

/* Exercise the real parser/FSM with deterministic ioctl replies, without root. */
static unsigned long long active_watch, generation;
static bool fail_arm;

/*
 * Simulate watch configuration, empty match replies, and injected arm failures
 * for FSM unit tests.
 */
int __wrap_ioctl(int fd, unsigned long command, ...)
{
	va_list ap;
	unsigned long long *value;

	(void)fd;
	va_start(ap, command);
	if (command == SYSMON_GET_MATCH) {
		va_end(ap);
		errno = EAGAIN;
		return -1;
	}
	if (command == SYSMON_SET_MODE) {
		assert(va_arg(ap, unsigned long) == SYSMON_OFF);
		va_end(ap);
		active_watch = 0;
		return 0;
	}
	value = va_arg(ap, unsigned long long *);
	va_end(ap);
	if (command == SYSMON_GET_WATCH) {
		*value = active_watch;
		return 0;
	}
	assert(command == SYSMON_SET_WATCH);
	assert(*value >= SYSMON_OPEN && *value <= SYSMON_WRITE);
	if (fail_arm) {
		errno = EIO;
		return -1;
	}
	active_watch = (++generation << 8) | *value;
	*value = active_watch;
	return 0;
}

/*
 * Write a temporary JSON fixture, pass it to the real FSM loader, and remove
 * the fixture.
 */
static int load_json(const void *json, size_t length, struct sysmon_fsm *fsm)
{
	char path[] = "/tmp/sysmon-fsm-test-XXXXXX";
	int fd = mkstemp(path), result;
	FILE *file;

	assert(fd >= 0);
	file = fdopen(fd, "wb");
	assert(file);
	assert(fwrite(json, 1, length, file) == length);
	assert(fclose(file) == 0);
	result = sysmon_fsm_load(path, fsm);
	assert(unlink(path) == 0);
	return result;
}

/*
 * Check valid FSM JSON and rejection of malformed input, unsupported states,
 * and oversized inputs.
 */
static void test_json(void)
{
	const char *valid = " { \"states\" : [\"open\", \"read\", \"wr\\u0069te\"] }\n";
	const char *invalid[] = {
		"", "{}", "{\"states\":[]}", "{\"states\":[\"close\"]}",
		"{\"states\":[\"read\",]}", "{\"states\":[42]}",
		"{\"states\":[\"read\"]} trailing", "{\"states\":[\"read\"]",
		"{\"states\":[\"read\"],\"states\":[\"write\"]}",
		"{\"states\":[\"read\\u0000\"]}", "{\"states\":[\"\\x72ead\"]}",
		"{\"states\":[\"read\"],\"extra\":true}", "[\"read\"]"
	};
	struct sysmon_fsm fsm = { 0 };
	char excessive[4096] = "{\"states\":[";
	char *large = malloc(65537);
	size_t i;

	assert(load_json(valid, strlen(valid), &fsm) == 0);
	assert(fsm.count == 3 && fsm.states[0] == SYSMON_OPEN &&
	       fsm.states[1] == SYSMON_READ && fsm.states[2] == SYSMON_WRITE);
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
		assert(load_json(invalid[i], strlen(invalid[i]), &fsm) == -1);
	assert(load_json("{\"states\":[\"read\"]}\0", 20, &fsm) == -1);
	for (i = 0; i < SYSMON_FSM_MAX_STATES; i++)
		strcat(excessive, i ? ",\"read\"" : "\"read\"");
	strcat(excessive, "]}");
	assert(load_json(excessive, strlen(excessive), &fsm) == 0);
	excessive[strlen(excessive) - 2] = '\0';
	strcat(excessive, ",\"read\"]}");
	assert(load_json(excessive, strlen(excessive), &fsm) == -1);
	assert(large);
	memset(large, ' ', 65537);
	assert(load_json(large, 65537, &fsm) == -1);
	free(large);
}

/*
 * Check ordered FSM transitions, repeated states, stale-token rejection, and
 * looping behavior.
 */
static void test_sequence(void)
{
	struct sysmon_fsm fsm = { .states = {SYSMON_OPEN, SYSMON_READ, SYSMON_WRITE}, .count = 3 };
	struct sysmon_record record = { .wall_ns = 123, .seq = 1, .pid = 456 };
	FILE *log = tmpfile();
	char line[1024];
	size_t i;
	unsigned long long initial;

	assert(log && sysmon_fsm_start(0, log, &fsm) == 0);
	initial = fsm.watch;
	record.op = SYSMON_WRITE;
	record.watch = fsm.watch;
	assert(!sysmon_fsm_matches(&fsm, &record));
	assert(sysmon_fsm_advance(0, log, &fsm, &record) == 0 && fsm.current == 0);
	for (i = 0; i < 6; i++) {
		record.op = fsm.states[fsm.current];
		record.watch = fsm.watch;
		record.blocked = 1;
		assert(!sysmon_fsm_matches(&fsm, &record));
		record.blocked = 0;
		assert(sysmon_fsm_matches(&fsm, &record));
		assert(sysmon_fsm_advance(0, log, &fsm, &record) == 0);
		assert(fsm.current == (i + 1) % 3);
		assert(!sysmon_fsm_matches(&fsm, &record));
	}
	assert(fsm.cycles == 2);
	record.op = SYSMON_OPEN;
	record.watch = initial;
	assert(!sysmon_fsm_matches(&fsm, &record));
	rewind(log);
	assert(fgets(line, sizeof(line), log) && strstr(line, "\033[36mFSM start"));
	assert(fgets(line, sizeof(line), log) && !strcmp(line, "\n"));
	assert(fgets(line, sizeof(line), log) && strstr(line, "FSM transition") &&
	       strstr(line, "captured_ns=123") && strstr(line, "logged_ns=") &&
	       strstr(line, "from=1(open) current_state=2/3 expected=read") &&
	       strstr(line, "\033[0m\n"));
	assert(fgets(line, sizeof(line), log) && !strcmp(line, "\n"));
	fclose(log);
	/* Same-op adjacent states and single-state loops require a fresh watch. */
	for (i = 1; i <= 2; i++) {
		fsm = (struct sysmon_fsm) { .states = {SYSMON_READ, SYSMON_READ}, .count = i };
		log = tmpfile();
		assert(log && sysmon_fsm_start(0, log, &fsm) == 0);
		record.op = SYSMON_READ;
		record.watch = fsm.watch;
		fail_arm = true;
		assert(sysmon_fsm_advance(0, log, &fsm, &record) == -1);
		assert(fsm.current == 0 && fsm.watch == record.watch);
		fail_arm = false;
		assert(sysmon_fsm_advance(0, log, &fsm, &record) == 0);
		assert(!sysmon_fsm_matches(&fsm, &record));
		active_watch = 0;
		assert(sysmon_fsm_check(0, &fsm) == -1);
		fclose(log);
	}
}

/* Check valid and invalid combinations of command-line FSM options. */
static void test_options(void)
{
	struct sysmon_options options;
	char *defaults[] = {"sysmonctl", "--log", "--file", NULL};
	char *custom[] = {"sysmonctl", "--file", "custom.json", "--log", NULL};
	char *bad_mode[] = {"sysmonctl", "--off", "--file", NULL};
	char *bad_status[] = {"sysmonctl", "--log", "--file", "--status", NULL};
	char *missing_block[] = {"sysmonctl", "--block", "--pid", "123", NULL};
	char *once[] = {"sysmonctl", "--log", "--file", "--once", NULL};
	char *bad_once[] = {"sysmonctl", "--log", "--once", NULL};

	optind = 0;
	assert(sysmon_parse_commands(3, defaults, &options) == 0 && options.collect);
	assert(!strcmp(options.fsm_path, "fsm.json"));
	optind = 0;
	assert(sysmon_parse_commands(4, custom, &options) == 0);
	assert(!strcmp(options.fsm_path, "custom.json"));
	optind = 0;
	assert(sysmon_parse_commands(3, bad_mode, &options) == -1);
	optind = 0;
	assert(sysmon_parse_commands(4, bad_status, &options) == -1);
	optind = 0;
	assert(sysmon_parse_commands(4, missing_block, &options) == -1);
	optind = 0;
	assert(sysmon_parse_commands(4, once, &options) == 0 && options.once && options.collect);
	optind = 0;
	assert(sysmon_parse_commands(3, bad_once, &options) == -1);
}

/*
 * Check that a single FSM cycle switches OFF without rearming, including
 * watch-update failures.
 */
static void test_once(void)
{
	const char *cases[] = {
		"{\"states\":[\"write\"]}",
		"{\"states\":[\"read\",\"read\"]}",
		"{\"states\":[\"read\",\"write\",\"read\",\"read\"]}",
		"{\"states\":[\"write\",\"open\",\"write\",\"read\"]}"
	};
	size_t i, j;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct sysmon_fsm fsm;
		struct sysmon_record record = { 0 };
		unsigned long long start_generation;
		char line[1024];
		size_t transitions = 0;
		FILE *log = tmpfile();

		assert(log && load_json(cases[i], strlen(cases[i]), &fsm) == 0);
		fsm.once = true;
		assert(sysmon_fsm_start(0, log, &fsm) == 0);
		start_generation = generation;
		for (j = 0; j < fsm.count; j++) {
			assert(fsm.current == j && fsm.cycles == 0 && active_watch != 0);
			record.op = fsm.states[j];
			record.watch = fsm.watch;
			assert(sysmon_fsm_advance(0, log, &fsm, &record) == 0);
			/* Entering state N is not completion: its own fresh event is required. */
			if (j + 1 < fsm.count)
				assert(fsm.current == j + 1 && fsm.cycles == 0 && active_watch != 0);
			assert(!sysmon_fsm_matches(&fsm, &record));
		}
		assert(fsm.cycles == 1 && fsm.current == 0 && fsm.watch == 0 && active_watch == 0);
		assert(generation == start_generation + fsm.count - 1);
		record.op = fsm.states[0];
		record.watch = 0;
		assert(!sysmon_fsm_matches(&fsm, &record));
		assert(sysmon_fsm_advance(0, log, &fsm, &record) == 0 && fsm.cycles == 1);
		rewind(log);
		while (fgets(line, sizeof(line), log)) {
			if (!strstr(line, "FSM transition"))
				continue;
			transitions++;
			assert(strncmp(line, "\033[36m", 5) == 0 && strstr(line, "\033[0m\n"));
			if (transitions == fsm.count)
				assert(strstr(line, "mode=off") && strstr(line, "current_state=1/") &&
				       strstr(line, "cycles=1 watch=0"));
		}
		assert(transitions == fsm.count);
		fclose(log);
	}
}

/*
 * Run the FSM JSON, transition, CLI-option, and single-cycle regression
 * checks.
 */
int main(void)
{
	test_options();
	test_json();
	test_sequence();
	test_once();
	puts("PASS: FSM JSON, CLI, transitions, looping, stale events, colors and ioctl failures");
	return 0;
}
