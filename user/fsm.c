/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <string.h>
#include <time.h>
#include "sysmon_user.h"

/* A bounded parser for the documented JSON schema, not a general JSON tree.
 * JSON whitespace and escaped ASCII names (including \uXXXX) are supported.
 * Reject unknown keys, extra values, embedded NULs and trailing commas/data.
 */
struct parser {
	const unsigned char *cursor, *end;
};

/* Advance the JSON cursor past whitespace without reading beyond the input. */
static void whitespace(struct parser *p)
{
	while (p->cursor < p->end &&
	       (*p->cursor == ' ' || *p->cursor == '\t' ||
		*p->cursor == '\r' || *p->cursor == '\n'))
		p->cursor++;
}

/* Skip JSON whitespace and consume the expected character if present. */
static bool consume(struct parser *p, unsigned char c)
{
	whitespace(p);
	if (p->cursor == p->end || *p->cursor != c)
		return false;
	p->cursor++;
	return true;
}

/*
 * Convert one hexadecimal digit to its value, returning -1 for other
 * characters.
 */
static int hex_digit(unsigned char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/*
 * Decode a bounded ASCII JSON string, validating escapes and rejecting invalid
 * or oversized values.
 */
static bool string(struct parser *p, char *out, size_t capacity)
{
	size_t used = 0;

	if (!consume(p, '"'))
		return false;
	while (p->cursor < p->end) {
		unsigned int c = *p->cursor++;

		if (c == '"') {
			out[used] = '\0';
			return true;
		}
		if (c < 0x20 || c > 0x7f)
			return false;
		if (c == '\\') {
			if (p->cursor == p->end)
				return false;
			c = *p->cursor++;
			switch (c) {
			case '"': case '\\': case '/': break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'u': {
				int i;

				c = 0;
				for (i = 0; i < 4; i++) {
					int digit;

					if (p->cursor == p->end ||
					    (digit = hex_digit(*p->cursor++)) < 0)
						return false;
					c = c * 16 + (unsigned int)digit;
				}
				if (!c || c > 0x7f)
					return false;
				break;
			}
			default: return false;
			}
		}
		if (used + 1 >= capacity)
			return false;
		out[used++] = (char)c;
	}
	return false;
}

/*
 * Load and validate the ordered syscall states from a bounded JSON file
 * without changing device settings.
 */
int sysmon_fsm_load(const char *path, struct sysmon_fsm *fsm)
{
	unsigned char data[65537];
	struct sysmon_fsm parsed = { 0 };
	struct parser p;
	char name[16];
	size_t length;
	FILE *file = fopen(path, "rb");

	if (!file) {
		fprintf(stderr, "Cannot open FSM file %s: %s\n", path, strerror(errno));
		return -1;
	}
	length = fread(data, 1, sizeof(data), file);
	if (ferror(file)) {
		fprintf(stderr, "Cannot read FSM file %s: %s\n", path, strerror(errno));
		fclose(file);
		return -1;
	}
	if (fclose(file)) {
		fprintf(stderr, "Cannot close FSM file %s: %s\n", path, strerror(errno));
		return -1;
	}
	p = (struct parser) { .cursor = data, .end = data + length };
	if (length > 65536 || !consume(&p, '{') ||
	    !string(&p, name, sizeof(name)) || strcmp(name, "states") ||
	    !consume(&p, ':') || !consume(&p, '['))
		goto invalid;
	do {
		int op;

		if (parsed.count == SYSMON_FSM_MAX_STATES ||
		    !string(&p, name, sizeof(name)))
			goto invalid;
		if (!strcmp(name, "open")) op = SYSMON_OPEN;
		else if (!strcmp(name, "read")) op = SYSMON_READ;
		else if (!strcmp(name, "write")) op = SYSMON_WRITE;
		else goto invalid;
		parsed.states[parsed.count++] = op;
	} while (consume(&p, ','));
	if (!consume(&p, ']') || !consume(&p, '}'))
		goto invalid;
	whitespace(&p);
	if (p.cursor != p.end)
		goto invalid;
	*fsm = parsed;
	printf("Loaded FSM from %s: %zu ordered states.\n", path, fsm->count);
	return 0;
invalid:
	fprintf(stderr, "Invalid FSM JSON in %s at byte %zu: expected "
		"{\"states\":[\"open\",\"read\",\"write\"]}, with 1-%d states "
		"and at most 65536 bytes.\n", path, (size_t)(p.cursor - data),
		SYSMON_FSM_MAX_STATES);
	return -1;
}

/*
 * Request a watch for the next syscall category and save the token returned by
 * the kernel.
 */
static int arm(int fd, int op, unsigned long long *watch)
{
	unsigned long long requested = (unsigned long long)op;

	if (ioctl(fd, SYSMON_SET_WATCH, &requested) < 0) {
		fprintf(stderr, "Cannot arm FSM syscall %s: %s\n",
			sysmon_op_name(op), strerror(errno));
		return -1;
	}
	*watch = requested;
	return 0;
}

/*
 * Append and flush a colored FSM start or transition message to the log and
 * console.
 *
 * Each line is one append, uses a fixed color, and contains no unescaped text
 * from the event.
 */
static int announce(FILE *file, const struct sysmon_fsm *fsm, size_t previous,
		    const struct sysmon_record *record)
{
	char line[768];
	struct timespec now;
	unsigned long long logged;
	int length;

	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -1;
	logged = (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
	if (record)
		length = snprintf(line, sizeof(line),
			"\033[36mFSM transition mode=%s observed=%s pid=%d tid=%d "
			"captured_ns=%llu logged_ns=%llu seq=%llu "
			"from=%zu(%s) current_state=%zu/%zu expected=%s cycles=%llu watch=%llu\033[0m\n\n",
			fsm->once && fsm->cycles ? "off" : "log",
			sysmon_op_name(record->op), record->pid, record->tid,
			record->wall_ns, logged, record->seq,
			previous + 1, sysmon_op_name(fsm->states[previous]),
			fsm->current + 1, fsm->count, sysmon_op_name(fsm->states[fsm->current]),
			fsm->cycles, fsm->watch);
	else
		length = snprintf(line, sizeof(line),
			"\033[36mFSM start mode=log logged_ns=%llu current_state=1/%zu "
			"expected=%s cycles=0 watch=%llu\033[0m\n\n",
			logged, fsm->count, sysmon_op_name(fsm->states[0]), fsm->watch);
	if (length < 0 || (size_t)length >= sizeof(line))
		return -1;
	if (fputs(line, file) == EOF || fflush(file) ||
	    printf("%s", line) < 0 || fflush(stdout)) {
		fprintf(stderr, "Cannot write FSM state message: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Reset FSM progress, arm the first state, verify match delivery is supported,
 * and announce startup.
 */
int sysmon_fsm_start(int fd, FILE *log_file, struct sysmon_fsm *fsm)
{
	struct sysmon_record record;

	fsm->current = 0;
	fsm->cycles = 0;
	if (arm(fd, fsm->states[0], &fsm->watch))
		return -1;
	/* Check the notification ABI now rather than waiting forever on an old
	 * module. GET_MATCH is non-consuming; an early match remains pending.
	 */
	if (sysmon_fsm_receive(fd, fsm, &record) < 0)
		return -1;
	return announce(log_file, fsm, 0, NULL);
}

/*
 * Fetch a dedicated match; return one for a valid current match, zero for no
 * usable match, or -1 on error.
 */
int sysmon_fsm_receive(int fd, const struct sysmon_fsm *fsm, struct sysmon_record *record)
{
	if (ioctl(fd, SYSMON_GET_MATCH, record) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		fprintf(stderr, "Cannot receive FSM match notification: %s%s\n", strerror(errno),
			errno == ENOTTY ? " (rebuild and reload sysmon)" : "");
		return -1;
	}
	return sysmon_fsm_matches(fsm, record) ? 1 : 0;
}

/*
 * Check that a record matches the current watch and expected operation of an
 * unfinished FSM.
 */
bool sysmon_fsm_matches(const struct sysmon_fsm *fsm, const struct sysmon_record *record)
{
	return !(fsm->once && fsm->cycles) && !record->blocked && record->watch == fsm->watch &&
	       record->op == fsm->states[fsm->current];
}

/*
 * Verify that the kernel watch still matches the FSM, detecting external
 * configuration changes.
 */
int sysmon_fsm_check(int fd, const struct sysmon_fsm *fsm)
{
	unsigned long long watch;

	if (ioctl(fd, SYSMON_GET_WATCH, &watch) < 0) {
		fprintf(stderr, "Cannot inspect FSM watch: %s\n", strerror(errno));
		return -1;
	}
	if (watch != fsm->watch) {
		fprintf(stderr, "FSM watch changed by another controller; stopping collection.\n");
		return -1;
	}
	return 0;
}

/*
 * Advance on a valid match, arming the next state or switching OFF after a
 * single cycle, and announce the transition.
 */
int sysmon_fsm_advance(int fd, FILE *log_file, struct sysmon_fsm *fsm,
		       const struct sysmon_record *record)
{
	size_t previous = fsm->current;
	size_t next = (previous + 1) % fsm->count;
	unsigned long long watch;

	if (!sysmon_fsm_matches(fsm, record))
		return 0;
	if (sysmon_fsm_check(fd, fsm))
		return -1;
	if (fsm->once && !next) {
		/* Stop before rearming state 1: the pending match cannot start cycle 2. */
		if (ioctl(fd, SYSMON_SET_MODE, (unsigned long)SYSMON_OFF) < 0) {
			fprintf(stderr, "Cannot stop FSM after one cycle: %s\n", strerror(errno));
			return -1;
		}
		watch = 0;
	} else if (arm(fd, fsm->states[next], &watch)) {
		return -1;
	}
	fsm->current = next;
	fsm->watch = watch;
	if (!next)
		fsm->cycles++;
	return announce(log_file, fsm, previous, record);
}
