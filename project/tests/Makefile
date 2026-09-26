CC ?= cc
CPPFLAGS += -I../include
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -pthread
LDLIBS += -pthread

.PHONY: all check check-kernel check-fsm check-timestamp check-performance clean
PROGRAMS = test_modes bench_latency bench_impact test_block test_control test_fsm test_fsm_collect test_timestamp syscall_worker
all: $(PROGRAMS)

test_modes: test_modes.c ../include/sysmon.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ test_modes.c $(LDLIBS)

bench_latency bench_impact test_block: %: %.c perf_common.c perf_common.h ../include/sysmon.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< perf_common.c $(LDLIBS)

test_control: test_control.c ../include/sysmon.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

syscall_worker: syscall_worker.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

test_fsm: test_fsm.c ../user/fsm.c ../user/commands.c ../user/sysmon_user.h ../include/sysmon.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -D_POSIX_C_SOURCE=200809L $(LDFLAGS) -o $@ test_fsm.c ../user/fsm.c ../user/commands.c -Wl,--wrap=ioctl $(LDLIBS)

test_fsm_collect: test_fsm_collect.c ../user/fsm.c ../user/commands.c ../user/log.c ../user/metrics.c ../user/sysmon_user.h ../include/sysmon.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -D_POSIX_C_SOURCE=200809L $(LDFLAGS) -o $@ test_fsm_collect.c ../user/fsm.c ../user/commands.c ../user/log.c ../user/metrics.c -Wl,--wrap=ioctl,--wrap=poll,--wrap=read,--wrap=__poll_chk,--wrap=__read_chk $(LDLIBS)

check-fsm: test_fsm test_fsm_collect
	./test_fsm
	./test_fsm_collect

test_timestamp: test_timestamp.c ../user/log.c ../user/fsm.c ../user/commands.c ../user/metrics.c ../user/sysmon_user.h ../include/sysmon.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -D_POSIX_C_SOURCE=200809L $(LDFLAGS) -o $@ test_timestamp.c ../user/fsm.c ../user/commands.c ../user/metrics.c -Wl,--wrap=gmtime_r,--wrap=strftime $(LDLIBS)

check-timestamp: test_timestamp
	./test_timestamp

check: check-fsm check-timestamp check-performance

# Explicit privileged check: module loaded, initially OFF, no collector attached.
check-kernel: test_modes
	./test_modes

check-performance: bench_latency bench_impact
	python3 check_loads.py

# For an initramfs: make LDFLAGS=-static
clean:
	rm -f $(PROGRAMS) bench
