#!/bin/sh
# Functional checks, then repeated EPERM and side-effect checks under load.
SUITE=block
. "$(dirname -- "$0")/perf_common.sh"
"$ROOT/tests/test_block" --header > "$OUTPUT/trials.csv"
load_module
"$ROOT/tests/test_modes" > "$OUTPUT/functional.log" 2>&1
run_condition open
run_condition read
run_condition write
unload_module
printf 'complete\n' > "$OUTPUT/COMPLETE"
printf 'Blocking data: %s\nGraph: python3 tests/plot_loads.py --results "%s"\n' "$OUTPUT" "$OUTPUT"
