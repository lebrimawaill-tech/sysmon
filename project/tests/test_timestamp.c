/* SPDX-License-Identifier: GPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <limits.h>
#include <stdlib.h>

/* Exercise the private formatter without exporting a production test API. */
#include "../user/log.c"

static unsigned int conversions, formats;
static bool fail_conversion, fail_format;

/* Access the original libc UTC conversion function without the test wrapper. */
struct tm *__real_gmtime_r(const time_t *seconds, struct tm *utc);

/* Access the original libc time formatter without the test wrapper. */
size_t __real_strftime(char *out, size_t size, const char *format, const struct tm *utc);

/*
 * Count UTC conversions and optionally inject a conversion failure for cache
 * tests.
 */
struct tm *__wrap_gmtime_r(const time_t *seconds, struct tm *utc)
{
	++conversions;
	return fail_conversion ? NULL : __real_gmtime_r(seconds, utc);
}

/*
 * Count date formatting calls and optionally inject a failure that damages the
 * output buffer.
 */
size_t __wrap_strftime(char *out, size_t size, const char *format, const struct tm *utc)
{
	++formats;
	if (fail_format) {
		memset(out, '?', size);
		return 0;
	}
	return __real_strftime(out, size, format, utc);
}

/*
 * Compare the cached timestamp text with independently formatted UTC output
 * for the same nanoseconds.
 */
static void check(struct timestamp_cache *cache, unsigned long long ns)
{
	char actual[48], expected[48], date[32];
	time_t seconds = (time_t)(ns / 1000000000ULL);
	struct tm utc;

	assert(__real_gmtime_r(&seconds, &utc));
	assert(__real_strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &utc));
	assert(snprintf(expected, sizeof(expected), "%s.%09lluZ", date,
			ns % 1000000000ULL) > 0);
	assert(timestamp(actual, sizeof(actual), ns, cache) == 0);
	assert(strcmp(actual, expected) == 0);
}

/*
 * Check timestamp cache reuse, clock boundaries and backward jumps,
 * independent caches, truncation, and failure recovery.
 */
int main(void)
{
	struct log_timestamps caches = { 0 };
	struct timestamp_cache *cache = &caches.captured;
	char out[48];
	unsigned int before;
	unsigned long long random = 42;
	const unsigned long long edges[] = {
		0, 1, 999999999ULL, 1000000000ULL, 1000000001ULL,
		951782399999999999ULL, 951782400000000000ULL, /* leap day */
		1704067199999999999ULL, 1704067200000000000ULL, /* new year */
		2147483647999999999ULL, 2147483648000000000ULL, /* 2038 */
		ULLONG_MAX, 1000000000ULL, 0 /* backward jumps */
	};

	/* Independent old-capture/current-append caches must not evict each other. */
	for (unsigned int i = 0; i < 1000; ++i) {
		check(&caches.captured, 1000000000ULL + i);
		check(&caches.appended, 1704067200000000000ULL + i);
	}
	assert(conversions == 2 && formats == 2);
	for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i)
		check(cache, edges[i]);
	for (unsigned int i = 0; i < 10000; ++i) {
		random = random * 6364136223846793005ULL + 1;
		check(cache, random);
	}
	check(cache, 0);
	assert(timestamp(out, 30, 0, cache) == -1);
	assert(timestamp(out, 31, 0, cache) == 0);
	assert(strcmp(out, "1970-01-01T00:00:00.000000000Z") == 0);
	assert(timestamp(out, 0, 0, cache) == -1);
	/* A failed miss must not leave a valid key attached to a damaged prefix. */
	fail_format = true;
	assert(timestamp(out, sizeof(out), 1000000000ULL, cache) == -1);
	assert(!cache->valid);
	fail_format = false;
	before = conversions;
	check(cache, 0);
	assert(conversions == before + 1);
	fail_conversion = true;
	assert(timestamp(out, sizeof(out), 1000000000ULL, cache) == -1);
	assert(!cache->valid);
	fail_conversion = false;
	check(cache, 1000000000ULL);
	puts("PASS: cached timestamps match uncached UTC formatting; boundaries, backward jumps, independent caches, truncation and failures");
	return 0;
}
