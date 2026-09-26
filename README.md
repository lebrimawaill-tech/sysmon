# sysmon

sysmon is a Linux kernel module and command-line collector for observing
`open`, `read`, and `write` system calls. It supports three modes:

- **Off:** monitoring is disabled.
- **Log:** collect system-wide events, or follow an ordered sequence of
  operations using a JSON finite-state machine (FSM).
- **Block:** deny one operation for a selected process with `EPERM` and
  collect the denied events.

The kernel module uses kprobes. Ordinary events pass through a bounded ring
queue; FSM matches use a separate notification slot. The userspace program
writes timestamped entries to `sysmon.log`. Timestamp caching is implemented
in the collector.

## Requirements

Use native x86-64 Linux with matching kernel headers and kprobe support.
The project has been built on Ubuntu 25.10 with kernel `6.17.0-41-generic`.
Other kernels must provide the syscall wrapper symbols used by the module;
compatibility with every kernel is not guaranteed. Windows, macOS, and
32-bit syscall compatibility paths are not supported.

On Ubuntu, install the build and test dependencies:

```sh
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) kmod util-linux python3 python3-matplotlib
```

Python and Matplotlib are used by the analysis and unprivileged test suite.
The module and collector themselves are written in C. For a Python virtual
environment instead, install the packages in `tests/requirements.txt`.

Loading the module and controlling `/dev/sysmon` require root privileges in
the host PID namespace. Use a development machine or VM where you can load
kernel modules. Module-signature enforcement can prevent an unsigned module
from loading.

## Compile

Clone this repository and open its root directory. All commands below assume
that working directory unless stated otherwise.

```sh
make kmod user tests
```

This produces `kmod/sysmon.ko`, `user/sysmonctl`, and the test executables.
Compilation does not require `sudo`. To build only the userspace programs:

```sh
make user tests
```

## Run the collector

Load the module and inspect its initial off state:

```sh
sudo insmod kmod/sysmon.ko
sudo ./user/sysmonctl --status
```

Start ordinary logging:

```sh
sudo ./user/sysmonctl --log
```

The collector prints observations and appends to `sysmon.log` in its current
working directory. Logging observes system-wide operations; `--pid` configures
blocking and does not filter ordinary logging. Only one collector can own
event delivery at a time.

Press **Ctrl-C** to stop collection. This alone does not disable the module's
current mode. Disable monitoring explicitly, then unload after the collector
has exited:

```sh
sudo ./user/sysmonctl --off
sudo rmmod sysmon
```

For all command-line options:

```sh
./user/sysmonctl --help
```

## Run an FSM

An FSM watches operations in the order listed in its JSON `states` array.
To run the repository's current configuration for one cycle, with the module
loaded:

```sh
sudo ./user/sysmonctl --log --file fsm.json --once
```

The supplied `fsm.json` currently contains `write, read, read, read, read`.
Repeated entries are separate states. For a simple `open → read → write`
example, create a separate file without overwriting that configuration:

```sh
cat > /tmp/sysmon-fsm-example.json <<'EOF'
{"states": ["open", "read", "write"]}
EOF
sudo ./user/sysmonctl --log --file /tmp/sysmon-fsm-example.json --once
```

Only a match for the currently expected operation advances the FSM.
Matches are system-wide, so successive states can be satisfied by different
processes. Each displayed FSM observation corresponds to a matched state;
unrelated operations do not appear as FSM observations. With `--once`, the
collector exits and switches the module off after one complete cycle.
Without `--once`, the sequence repeats until collection is stopped.

## Block an operation

With the module loaded, replace `12345` with the PID of a test process you
control, then run:

```sh
sudo ./user/sysmonctl --block --pid 12345 --syscall write
```

Matching calls from that process's threads return `EPERM`; denied entries
are logged in red. Supported operation names are `open`, `read`, and `write`.
The `open` category also covers `openat` and `openat2`. Stop collection with
Ctrl-C and run `sudo ./user/sysmonctl --off` to remove the active blocking mode.
The automated blocking test below supplies its own controlled worker process.

## Run tests

Run the unprivileged checks after installing the dependencies:

```sh
make check
```

These cover FSM parsing and transitions, collector behavior, timestamp
formatting and caching, and workload/analysis validation. They do not load
the kernel module.

For live tests, first stop any collector and unload any manually loaded
module. Build with `make kmod user tests`, then run:

```sh
sudo ./tests/run_fsm.sh --file /tmp/sysmon-fsm-example.json
sudo ./tests/run_block_log.sh
```

The FSM command uses the example file created above and verifies an actual
`open → read → write` cycle. The blocking test verifies denied operations and
their real collector log entries. Both scripts load and unload their own
module and create a unique output directory beneath `tests/results/`.

Run the three performance suites separately:

```sh
sudo ./tests/run_latency.sh
sudo ./tests/run_impact.sh
sudo ./tests/run_block.sh
python3 tests/plot_loads.py --results tests/results
```

| Suite | Measurement | Default trials |
| --- | --- | --- |
| Latency | Capture-to-receipt and capture-to-append delay, plus coverage | 4 loads × 3 repetitions = 12 |
| Impact | Transaction response time across five configurations | 5 configurations × 4 loads × 3 repetitions = 60 |
| Blocking | Denial correctness, side effects, and achieved attempt rate | 3 operations × 4 loads × 3 repetitions = 36 |

The default target rates are 3,000, 30,000, and 50,000 monitored calls/s,
plus unpaced operation (`--rates "3000 30000 50000 0"`). Each trial is bounded
by 250 ms or 20,000 transactions; the blocking test counts individual attempts.
Analysis uses achieved rates and reports event coverage because overloaded
logging can drop events.

The scripts create missing output directories and their parents. They refuse
to overwrite an existing result directory. For another run, select a fresh
path, for example:

```sh
sudo ./tests/run_latency.sh --output tests/results/latency-second
python3 tests/plot_loads.py --results tests/results/latency-second
```

Use a runner's `--help` for additional options. Run live suites sequentially;
they share one module and use a lock to prevent concurrent runs. Normal test
and plotting commands do not generate LaTeX files.

## Repository layout

| Path | Purpose |
| --- | --- |
| `include/` | Shared kernel/userspace protocol |
| `kmod/` | Kernel module, probes, event delivery, and mode control |
| `user/` | CLI, collector, FSM, metrics, and timestamp formatting |
| `tests/` | Functional tests, benchmark workloads, runners, and analysis |
| `fsm.json` | Editable runtime FSM configuration |

Generated binaries, logs, results, and figures are excluded by `.gitignore`.
They are created locally by the build and test commands. Inspect logs before
sharing them separately: system-wide observations can contain process names
and file paths.

The Makefile also retains report-generation targets, but this source checkout
does not include `report.tex` or the archived measurement datasets required
by `make report`. Building and running sysmon does not depend on the report.

## Troubleshooting and cleanup

- **`/dev/sysmon: Permission denied`:** run `sysmonctl` with `sudo`; the device
  is intentionally created with mode `0600` and also checks administrative
  privileges.
- **`/dev/sysmon` is missing:** load the module first. Inspect `sudo dmesg`
  if `insmod` fails.
- **Kernel build directory is missing:** install headers matching
  `uname -r`, then rebuild.
- **`Invalid module format`:** rebuild against the running kernel and inspect
  `sudo dmesg` for the specific mismatch.
- **Signature/key rejection:** use a module signed and trusted by your
  machine's kernel policy.
- **Module or collector already in use:** stop the existing collector,
  disable monitoring, and unload the module before starting an independent
  live test. An open device descriptor prevents unloading.
- **Output directory already exists:** pass a fresh `--output` path to keep
  previous measurements intact.

After stopping collection and unloading the module, remove build products with:

```sh
make clean
```

Saved test results remain available after this command.
