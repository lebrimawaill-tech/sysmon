#!/bin/sh
# Shared lifecycle and options for the three direct test scripts.
# Sourced after the caller sets SUITE=latency, impact, or block.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CTL=$ROOT/user/sysmonctl
CONTROL=$ROOT/tests/test_control
OUTPUT=$ROOT/tests/results/$SUITE
RATES='3000 30000 50000 0'
TRIALS=3
DURATION=250
MAXIMUM=20000
LOADED=0
COLLECTOR=
WORKER=

die() { printf 'Test error: %s\n' "$*" >&2; exit 1; }
integer() {
	case "$2" in ''|*[!0-9]*) die "$1 must be an integer";; esac
	case "$2" in 0[0-9]*) die "$1 must use decimal without leading zeros";; esac
	[ "$2" -ge "$3" ] && [ "$2" -le "$4" ] || die "$1 must be $3..$4"
}
usage() {
	cat <<EOF
Usage: sudo ./tests/run_$SUITE.sh [options]
  --rates "3000 30000 50000 0"    Requested monitored syscalls/s; 0 = maximum
  --duration-ms 250              Duration of each rate/trial (max 60000)
  --trials 3                    Repetitions per condition
  --max-transactions 20000       Cap to bound work and metric-buffer use
  --output DIR                  New output directory; missing parents are created

This script loads its own module and unloads it at exit. It refuses an already
loaded sysmon. No VM is used. Run 'make kmod user tests' first.
Optional WORKLOAD_CPU/COLLECTOR_CPU pin CPU lists with taskset.
Graphs: python3 tests/plot_loads.py --results "DIR"
EOF
}
while [ "$#" -gt 0 ]; do
	case "$1" in
	--help|-h) usage; exit 0;;
	--rates|--duration-ms|--trials|--max-transactions|--output)
		[ "$#" -ge 2 ] || die "missing argument for $1"
		case "$1" in
		--rates) RATES=$2;; --duration-ms) DURATION=$2;; --trials) TRIALS=$2;;
		--max-transactions) MAXIMUM=$2;; --output) OUTPUT=$2;;
		esac
		shift 2;;
	*) die "unknown option $1";;
	esac
done
integer duration-ms "$DURATION" 1 60000
integer trials "$TRIALS" 1 100
integer max-transactions "$MAXIMUM" 1 60000
[ -n "$OUTPUT" ] || die 'output directory must not be empty'
[ -n "$RATES" ] || die 'supply at least one rate'
SEEN=' '
for RATE in $RATES; do
	integer rate "$RATE" 0 1000000000
	case "$SEEN" in *" $RATE "*) die "duplicate rate: $RATE";; esac
	SEEN="$SEEN$RATE "
done
[ "$(id -u)" -eq 0 ] || die 'run this script with sudo'
command -v flock >/dev/null || die 'flock is required (util-linux)'
mkdir -p /run/lock
exec 9>/run/lock/sysmon-tests.lock
flock -n 9 || die 'another sysmon test script is running'
[ ! -d /sys/module/sysmon ] || die 'sysmon is already loaded; stop your collector and unload it first'
BINARY=$ROOT/tests/bench_$SUITE
[ "$SUITE" != block ] || BINARY=$ROOT/tests/test_block
for TOOL in "$CTL" "$CONTROL" "$BINARY"; do
	[ -x "$TOOL" ] || die "missing $TOOL; run make kmod user tests"
done
if [ "$SUITE" = block ]; then [ -x "$ROOT/tests/test_modes" ] || die 'build tests/test_modes'; fi
[ -f "$ROOT/kmod/sysmon.ko" ] || die 'missing kmod/sysmon.ko'
case "$OUTPUT" in /*) ;; *) OUTPUT="$PWD/$OUTPUT";; esac
[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || die "output exists: $OUTPUT (choose a fresh --output)"
# A checkout does not contain generated directories. Create parents first,
# then reserve a new run directory without reusing another run's files.
mkdir -p "$(dirname -- "$OUTPUT")"
mkdir "$OUTPUT"
OUTPUT=$(CDPATH= cd -- "$OUTPUT" && pwd)
FIXTURE=$OUTPUT/payload
printf '%s' '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > "$FIXTURE"

cleanup() {
	STATUS=$?
	trap - EXIT HUP INT TERM
	if [ -n "$WORKER" ]; then kill -TERM "$WORKER" 2>/dev/null || :; wait "$WORKER" 2>/dev/null || :; fi
	if [ "$LOADED" -eq 1 ]; then
		"$CTL" --off >/dev/null 2>&1 || :
		if [ -n "$COLLECTOR" ]; then kill -TERM "$COLLECTOR" 2>/dev/null || :; wait "$COLLECTOR" 2>/dev/null || :; fi
		rmmod sysmon || STATUS=1
	fi
	# Do not leave root-owned result trees when launched using sudo.
	if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
		chown -R "$SUDO_UID:$SUDO_GID" "$OUTPUT" || STATUS=1
	fi
	exit "$STATUS"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
{
	uname -a
	printf 'suite=%s\nrates=%s\ntrials=%s\nduration_ms=%s\nmax_transactions=%s\n' "$SUITE" "$RATES" "$TRIALS" "$DURATION" "$MAXIMUM"
	printf 'rate_units=monitored_syscalls_per_second\nclock=CLOCK_MONOTONIC\nconsole=regular_file\n'
	printf 'workload_cpu=%s\ncollector_cpu=%s\n' "${WORKLOAD_CPU:-scheduler}" "${COLLECTOR_CPU:-scheduler}"
	date -u '+date=%Y-%m-%dT%H:%M:%SZ'
} > "$OUTPUT/environment.txt"

load_module() {
	insmod "$ROOT/kmod/sysmon.ko"
	LOADED=1
	ATTEMPT=0
	while [ ! -c /dev/sysmon ]; do
		ATTEMPT=$((ATTEMPT + 1))
		[ "$ATTEMPT" -lt 500 ] || die '/dev/sysmon did not appear'
		sleep 0.01
	done
	"$CONTROL" --reset
}
unload_module() {
	"$CTL" --off >/dev/null
	rmmod sysmon
	LOADED=0
}
start_collector() {
	# RUN_DIR is unique for every rate, mode and trial: no stale queue state.
	"$CTL" --off > "$RUN_DIR/before.status"
	"$CONTROL" --reset
	"$CONTROL" --snapshot > "$RUN_DIR/before.stats"
	(
		cd "$RUN_DIR"
		set -- --log
		[ "$SUITE" != latency ] || set -- "$@" --metrics metrics.csv
		if [ -n "${COLLECTOR_CPU:-}" ]; then exec taskset -c "$COLLECTOR_CPU" "$CTL" "$@"; fi
		exec "$CTL" "$@"
	) > "$RUN_DIR/console.log" 2>&1 &
	COLLECTOR=$!
	ATTEMPT=0
	while ! grep -q 'Appending events to ./sysmon.log' "$RUN_DIR/console.log"; do
		kill -0 "$COLLECTOR" 2>/dev/null || die "collector failed: $RUN_DIR/console.log"
		ATTEMPT=$((ATTEMPT + 1))
		[ "$ATTEMPT" -lt 500 ] || die 'collector startup timeout'
		sleep 0.01
	done
}
stop_collector() {
	"$CTL" --off > "$RUN_DIR/after.status" 2>&1
	"$CONTROL" --drain
	kill -TERM "$COLLECTOR"
	if wait "$COLLECTOR"; then COLLECTOR=; else COLLECTOR=; die "collector failed: $RUN_DIR/console.log"; fi
	"$CONTROL" --snapshot > "$RUN_DIR/after.stats"
}
run_workload() {
	BINARY=$ROOT/tests/bench_$SUITE
	[ "$SUITE" != block ] || BINARY=$ROOT/tests/test_block
	(
		set -- --fixture "$FIXTURE" --scenario "$SCENARIO" --rate "$RATE" \
			--trial "$TRIAL" --duration-ms "$DURATION" --max-transactions "$MAXIMUM"
		[ "$SUITE" != block ] || set -- "$@" --operation "$SCENARIO"
		if [ -n "${WORKLOAD_CPU:-}" ]; then exec taskset -c "$WORKLOAD_CPU" "$BINARY" "$@"; fi
		exec "$BINARY" "$@"
	) > "$RUN_DIR/trial.csv" &
	WORKER=$!
	if wait "$WORKER"; then WORKER=; else WORKER=; cat "$RUN_DIR/trial.csv" >> "$OUTPUT/trials.csv"; die "workload failed in $RUN_DIR"; fi
	cat "$RUN_DIR/trial.csv" >> "$OUTPUT/trials.csv"
}
run_condition() {
	SCENARIO=$1
	for RATE in $RATES; do
		TRIAL=1
		while [ "$TRIAL" -le "$TRIALS" ]; do
			RUN_DIR=$OUTPUT/$SCENARIO/rate_$RATE/trial_$TRIAL
			mkdir -p "$RUN_DIR"
			printf '%s: %s, requested %s syscalls/s, trial %s\n\n' "$SUITE" "$SCENARIO" "$RATE" "$TRIAL"
			case "$SCENARIO" in verbose) start_collector;; esac
			run_workload
			case "$SCENARIO" in verbose) stop_collector;; esac
			TRIAL=$((TRIAL + 1))
		done
	done
}
