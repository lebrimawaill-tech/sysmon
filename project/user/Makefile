CC ?= cc
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -I../include
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror

.PHONY: all clean
all: sysmonctl

sysmonctl: main.o commands.o log.o metrics.o fsm.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

main.o commands.o log.o metrics.o fsm.o: sysmon_user.h ../include/sysmon.h

clean:
	$(RM) sysmonctl main.o commands.o log.o metrics.o fsm.o
