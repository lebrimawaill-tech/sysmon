#!/bin/sh
# Actual sysmonctl reaction latency at several syscall rates.
SUITE=latency
. "$(dirname -- "$0")/perf_common.sh"
"$ROOT/tests/bench_latency" --header > "$OUTPUT/trials.csv"
load_module
run_condition verbose
unload_module
printf 'complete\n' > "$OUTPUT/COMPLETE"
printf 'Latency data: %s\nGraph: python3 tests/plot_loads.py --results "%s"\n' "$OUTPUT" "$OUTPUT"
