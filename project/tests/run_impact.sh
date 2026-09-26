#!/bin/sh
# Response time of successful work, with pacing excluded from service time.
SUITE=impact
. "$(dirname -- "$0")/perf_common.sh"
"$ROOT/tests/bench_impact" --header > "$OUTPUT/trials.csv"
run_condition baseline
load_module
run_condition off
"$CTL" --pid 2147483647 --syscall write --block --status > "$OUTPUT/block_miss.status"
run_condition block_miss
"$CTL" --off >/dev/null
run_condition verbose
unload_module
run_condition baseline_after
printf 'complete\n' > "$OUTPUT/COMPLETE"
printf 'Impact data: %s\nGraph: python3 tests/plot_loads.py --results "%s"\n' "$OUTPUT" "$OUTPUT"
