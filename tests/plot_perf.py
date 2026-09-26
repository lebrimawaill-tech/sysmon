#!/usr/bin/env python3
"""Validate sysmon measurements and draw reproducible, standalone figures.

Usage: python3 tests/plot_perf.py [--results tests/results]
                                [--figures tests/figures]

Inputs are trials.csv and <scenario>/sysmon.log, plus metrics.csv for the
paced latency scenarios. Only records with the benchmark's PID captured
inside its measured interval are selected. The optional --design-only mode
draws architecture figures without requiring measurements.

LaTeX export requires --report-tex. Generated percentile macros use letters only, for example
\\PerfLatencyVerboseReceiveMedianUs and \\PerfLatencyVerboseAppendPNinetyNineUs.
"""

import argparse
import bisect
import csv
import json
import math
from pathlib import Path
import re
import statistics
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.ticker import PercentFormatter, ScalarFormatter


TRIAL_FIELDS = (
    "scenario", "trial", "pid", "iterations", "start_mono_ns", "end_mono_ns",
    "elapsed_ns", "expected_events", "errors",
)
METRIC_FIELDS = (
    "seq", "pid", "tid", "syscall", "blocked", "capture_mono_ns",
    "receive_mono_ns", "append_mono_ns",
)
ORDER = ["baseline", "off", "off_collector", "block_miss", "log_verbose", "baseline_after",
         "latency_verbose"]
LABELS = {
    "baseline": "Module absent", "baseline_after": "Module absent (recheck)",
    "off": "Off", "off_collector": "Off + collector",
    "block_miss": "Block: no match",
    "log_verbose": "Log: console enabled",
    "latency_verbose": "Paced: console enabled",
}
COLORS = {"baseline": "#777777", "baseline_after": "#AAAAAA", "off": "#56A5A9", "off_collector": "#82B7AA",
          "block_miss": "#A4A76B", "log_verbose": "#D58939",
          "latency_verbose": "#D58939"}
LOG_HEADER = re.compile(r"\bmono_ns=(\d+) seq=(\d+) pid=(\d+) tid=(\d+) ")


def ordered(names):
    return sorted(names, key=lambda name: (ORDER.index(name) if name in ORDER else 99, name))


def read_csv(path, required):
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        missing = set(required) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path}: missing CSV fields {', '.join(sorted(missing))}")
        yield from reader


def read_trials(path):
    trials = []
    seen = set()
    for row in read_csv(path, TRIAL_FIELDS):
        # Exclude archived scenarios outside the current comparison.
        if row["scenario"] not in ORDER:
            continue
        trial = {key: row[key] if key == "scenario" else int(row[key]) for key in TRIAL_FIELDS}
        key = (trial["scenario"], trial["trial"])
        if key in seen:
            raise ValueError(f"{path}: duplicate trial {key}")
        seen.add(key)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", trial["scenario"]):
            raise ValueError(f"{path}: invalid scenario name {trial['scenario']!r}")
        if (trial["pid"] <= 0 or trial["iterations"] <= 0 or trial["trial"] <= 0 or
                trial["expected_events"] < 0 or trial["start_mono_ns"] <= 0 or
                trial["end_mono_ns"] <= trial["start_mono_ns"]):
            raise ValueError(f"{path}: invalid bounds/counts in trial {key}")
        if trial["elapsed_ns"] != trial["end_mono_ns"] - trial["start_mono_ns"]:
            raise ValueError(f"{path}: elapsed time disagrees with interval in {key}")
        if trial["errors"]:
            raise ValueError(f"{path}: benchmark had {trial['errors']} errors in {key}")
        trial.update(observed_events=None, metric_events=0, receive_us=[], append_us=[])
        trials.append(trial)
    if not trials:
        raise ValueError(f"{path}: no measured trials")
    return trials


class TrialIndex:
    """Map a record to one measured interval without scanning every trial."""

    def __init__(self, trials):
        self.by_pid = {}
        for trial in trials:
            self.by_pid.setdefault(trial["pid"], []).append(trial)
        self.starts = {}
        for pid, entries in self.by_pid.items():
            entries.sort(key=lambda item: item["start_mono_ns"])
            for previous, current in zip(entries, entries[1:]):
                if previous["end_mono_ns"] > current["start_mono_ns"]:
                    raise ValueError(f"overlapping measured intervals for PID {pid}")
            self.starts[pid] = [entry["start_mono_ns"] for entry in entries]

    def match(self, pid, captured):
        if pid not in self.by_pid:
            return None
        offset = bisect.bisect_right(self.starts[pid], captured) - 1
        if offset < 0:
            return None
        trial = self.by_pid[pid][offset]
        return trial if captured < trial["end_mono_ns"] else None


def load_events(results, trials, notes):
    scenarios = {}
    for scenario in ordered({trial["scenario"] for trial in trials}):
        selected = [trial for trial in trials if trial["scenario"] == scenario]
        index = TrialIndex(selected)
        log_path = results / scenario / "sysmon.log"
        metrics_path = results / scenario / "metrics.csv"
        info = {"log_present": log_path.exists(), "metrics_present": metrics_path.exists(),
                "background_log_records": 0, "background_metric_records": 0,
                "negative_latencies_rejected": 0}
        scenarios[scenario] = info
        stats_fields = ("capture_n", "accepted_records", "delivered_records", "dropped", "queue_high", "read_batches")
        stats_paths = [results / scenario / name for name in ("before.stats", "after.stats")]
        collector_expected = (scenario == "off_collector" or
                              any(trial["expected_events"] for trial in selected))
        if collector_expected and not log_path.is_file():
            raise ValueError(f"{log_path}: required collector log missing; refusing incomplete measurements")
        if any(path.exists() for path in stats_paths) and not all(path.is_file() for path in stats_paths):
            raise ValueError(f"{scenario}: before.stats and after.stats must both be present")
        if all(path.exists() for path in stats_paths):
            before, after = [list(read_csv(path, stats_fields)) for path in stats_paths]
            if len(before) != 1 or len(after) != 1:
                raise ValueError(f"{scenario}: each before/after.stats file must contain one data row")
            delta = {field: int(after[0][field]) - int(before[0][field]) for field in stats_fields if field != "queue_high"}
            delta["queue_high"] = int(after[0]["queue_high"])
            if any(value < 0 for value in delta.values()):
                raise ValueError(f"{scenario}: a module counter decreased during collection")
            delta["mean_records_per_read"] = (delta["delivered_records"] / delta["read_batches"]
                                              if delta["read_batches"] else None)
            info["queue"] = delta
        if log_path.exists():
            for trial in selected:
                trial["observed_events"] = 0
            seen = set()
            with log_path.open(encoding="utf-8") as source:
                for number, line in enumerate(source, 1):
                    match = LOG_HEADER.search(line)
                    if not match:
                        raise ValueError(f"{log_path}:{number}: malformed event header")
                    captured, seq, pid, _tid = map(int, match.groups())
                    if seq in seen:
                        raise ValueError(f"{log_path}:{number}: duplicate sequence {seq}")
                    seen.add(seq)
                    trial = index.match(pid, captured)
                    if trial:
                        trial["observed_events"] += 1
                    else:
                        info["background_log_records"] += 1
        if metrics_path.exists():
            seen = set()
            for row in read_csv(metrics_path, METRIC_FIELDS):
                captured = int(row["capture_mono_ns"])
                trial = index.match(int(row["pid"]), captured)
                if trial is None:
                    info["background_metric_records"] += 1
                    continue
                seq = int(row["seq"])
                if seq in seen:
                    raise ValueError(f"{metrics_path}: duplicate benchmark sequence {seq}")
                seen.add(seq)
                received, appended = int(row["receive_mono_ns"]), int(row["append_mono_ns"])
                if not captured <= received <= appended:
                    raise ValueError(
                        f"{metrics_path}: rejected negative/nonordered latency for seq={seq}: "
                        f"capture={captured}, receive={received}, append={appended}")
                trial["metric_events"] += 1
                trial["receive_us"].append((received - captured) / 1000.0)
                trial["append_us"].append((appended - captured) / 1000.0)
        elif scenario.startswith("latency_"):
            raise ValueError(f"{metrics_path}: required timing measurements missing; refusing incomplete latency")
        for trial in selected:
            count, expected = trial["observed_events"], trial["expected_events"]
            if count is not None and count > expected:
                raise ValueError(f"{scenario} trial {trial['trial']}: {count} selected events "
                                 f"exceed expected {expected}; check workload/filtering")
            if count is not None and count < expected:
                notes.append(f"{scenario} trial {trial['trial']}: logged {count}/{expected} "
                             "benchmark events; missing events have unknown latency.")
            if metrics_path.exists() and count is not None and trial["metric_events"] != count:
                raise ValueError(f"{scenario} trial {trial['trial']}: metrics count "
                                 f"{trial['metric_events']} differs from log count {count}")
        if scenario.startswith("latency_") and not any(trial["metric_events"] for trial in selected):
            raise ValueError(f"{scenario}: no benchmark events survived for latency measurement")
    return scenarios


def quantile(values, probability):
    """Linear interpolation between ordered samples (the usual type-7 quantile)."""
    values = sorted(values)
    position = (len(values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def distribution(values):
    if not values:
        return None
    return {"n": len(values), "median": statistics.median(values),
            "p99": quantile(values, .99),
            "min": min(values), "max": max(values)}


def summarize(trials, scenarios, notes):
    output = {"method": {
        "clock": "CLOCK_MONOTONIC in kernel and userspace",
        "selection": "benchmark PID and start_mono_ns <= capture_mono_ns < end_mono_ns",
        "transaction": "one open, one read, one write, and one close; three monitored entries",
        "uncertainty": "observed trial min/max; not a confidence interval",
        "percentiles": "linear interpolation between ordered event samples",
        "append": "successful log fprintf/fflush return; not fsync or disk durability",
        "throughput_instrumentation": "metrics disabled",
        "latency_instrumentation": "optional collector metrics enabled",
    }, "scenarios": {}, "notes": notes}
    for scenario in ordered(scenarios):
        selected = [trial for trial in trials if trial["scenario"] == scenario]
        item = dict(scenarios[scenario])
        item["trials"] = len(selected)
        item["iterations"] = sum(trial["iterations"] for trial in selected)
        item["expected_events"] = sum(trial["expected_events"] for trial in selected)
        counts = [trial["observed_events"] for trial in selected]
        item["observed_events"] = sum(counts) if all(count is not None for count in counts) else None
        item["coverage_pct"] = (100 * item["observed_events"] / item["expected_events"]
                                if item["observed_events"] is not None and item["expected_events"] else None)
        item["receive_us"] = distribution([value for trial in selected for value in trial["receive_us"]])
        item["append_us"] = distribution([value for trial in selected for value in trial["append_us"]])
        if not scenario.startswith("latency_"):
            item["transaction_us"] = distribution([trial["elapsed_ns"] / trial["iterations"] / 1000
                                                   for trial in selected])
        item["per_trial"] = [{key: value for key, value in trial.items()
                              if key not in ("receive_us", "append_us")}
                             for trial in selected]
        output["scenarios"][scenario] = item
    baseline = output["scenarios"].get("baseline", {}).get("transaction_us")
    if baseline:
        for item in output["scenarios"].values():
            if "transaction_us" in item:
                item["slowdown_pct"] = 100 * (item["transaction_us"]["median"] / baseline["median"] - 1)
        if "baseline_after" in output["scenarios"]:
            output["baseline_drift_pct"] = output["scenarios"]["baseline_after"]["slowdown_pct"]
            if abs(output["baseline_drift_pct"]) >= 10:
                notes.append(f"The module-absent recheck differs by {output['baseline_drift_pct']:+.1f}% "
                             "from the initial baseline; scenario order/system drift limits the slowdown comparison.")
    else:
        notes.append("Module-absent baseline missing: slowdown percentages are unavailable.")
    return output


def save_figure(fig, figures, name):
    fig.savefig(figures / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(figures / f"{name}.png", dpi=180, bbox_inches="tight")
    plt.close(fig)


def draw_impact(summary, figures):
    scenarios = [(name, item) for name, item in summary["scenarios"].items() if "transaction_us" in item]
    if not scenarios:
        return
    fig, ax = plt.subplots(figsize=(11.4, 5.3))
    values = [item["transaction_us"]["median"] for _, item in scenarios]
    ax.bar(range(len(values)), values, width=.68, color=[COLORS.get(name, "#3978A8") for name, _ in scenarios], alpha=.8)
    for position, (name, item) in enumerate(scenarios):
        values = [trial["elapsed_ns"] / trial["iterations"] / 1000 for trial in item["per_trial"]]
        offsets = [0] if len(values) == 1 else [-.19 + .38 * i / (len(values) - 1) for i in range(len(values))]
        ax.scatter([position + offset for offset in offsets], values, s=27, facecolors="white", edgecolors="#202020", zorder=3)
        top = max(values)
        median = item["transaction_us"]["median"]
        label = f"{median:.2f} µs"
        if name != "baseline" and "slowdown_pct" in item:
            label += f"\n{item['slowdown_pct']:+.1f}%"
        ax.annotate(label, (position, top), xytext=(0, 9), textcoords="offset points", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(range(len(scenarios)), [LABELS.get(name, name).replace(": ", ":\n").replace(" + ", " +\n").replace(" (recheck)", "\n(recheck)") for name, _ in scenarios], fontsize=9)
    ax.set_ylabel("Time per sample transaction (µs; lower is faster)")
    ax.set_title("Impact on the sample program", loc="left", fontweight="bold")
    ax.set_ylim(0, ax.get_ylim()[1] * 1.23)
    ax.grid(axis="y", alpha=.2)
    ax.set_axisbelow(True)
    fig.text(.10, .01, "Bars: median of trials. Dots: every measured trial. Percent: change from module-absent median.\n"
             "One transaction = open + read + write + close. Timing CSV disabled; log scenarios retain ordinary text output.", fontsize=9)
    fig.tight_layout(rect=(0, .09, 1, 1))
    save_figure(fig, figures, "response_time")


def draw_latency(trials, figures):
    names = ordered({trial["scenario"] for trial in trials if trial["scenario"].startswith("latency_") and trial["receive_us"]})
    if not names:
        return
    fig, axes = plt.subplots(1, len(names), figsize=(5.3 * len(names), 4.6), squeeze=False, sharex=True, sharey=True)
    for ax, name in zip(axes[0], names):
        selected = [trial for trial in trials if trial["scenario"] == name]
        for field, label, color in [("receive_us", "Received in userspace", "#3978A8"),
                                    ("append_us", "Log append completed", "#D58939")]:
            values = sorted(value for trial in selected for value in trial[field])
            # A zero-nanosecond duration is placed at 1 ns on the logarithmic axis.
            ax.step([max(value, .001) for value in values], [100 * (i + 1) / len(values) for i in range(len(values))],
                    where="post", color=color, label=f"{label}\nMedian = {statistics.median(values):.1f} µs")
        ax.set_xscale("log")
        ax.xaxis.set_major_formatter(ScalarFormatter())
        ax.set_xlabel("Delay from syscall capture (µs; logarithmic scale)")
        ax.set_title(LABELS.get(name, name), loc="left", fontweight="bold")
        ax.set_ylim(0, 102)
        ax.grid(which="major", alpha=.2)
        ax.legend(loc="lower right", fontsize=8)
    axes[0][0].set_ylabel("Observed benchmark events (%)")
    fig.text(.08, .01, "A curve farther left means lower delay. Each curve includes all measured events.\n"
             "Paced workload; optional metrics enabled. Append completion means the OS accepted the log write, not disk durability.", fontsize=9)
    fig.tight_layout(rect=(0, .09, 1, 1))
    save_figure(fig, figures, "reaction_latency")


def draw_coverage(summary, figures):
    scenarios = [(name, item) for name, item in summary["scenarios"].items() if item["coverage_pct"] is not None]
    if not scenarios:
        return
    fig, ax = plt.subplots(figsize=(9.3, 4.5))
    ax.bar(range(len(scenarios)), [item["coverage_pct"] for _, item in scenarios], color=[COLORS.get(name, "#3978A8") for name, _ in scenarios], width=.65)
    for position, (_, item) in enumerate(scenarios):
        ax.text(position, item["coverage_pct"] + 2, f"{item['coverage_pct']:.1f}%\n{item['observed_events']:,}/{item['expected_events']:,}",
                ha="center", va="bottom", fontsize=9)
    ax.set_xticks(range(len(scenarios)), [LABELS.get(name, name).replace(": ", ":\n") for name, _ in scenarios], fontsize=9)
    ax.set_ylim(0, 121)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.yaxis.set_major_formatter(PercentFormatter())
    ax.set_ylabel("Benchmark events present in sysmon.log")
    ax.set_title("Did the logger keep up?", loc="left", fontweight="bold")
    ax.grid(axis="y", alpha=.2)
    ax.set_axisbelow(True)
    fig.text(.10, .01, "Counts select the benchmark PID and capture interval. The denominator is 3 × measured transactions.\n"
             "Missing events have unknown latency: read coverage together with latency and sample response time.", fontsize=9)
    fig.tight_layout(rect=(0, .10, 1, 1))
    save_figure(fig, figures, "event_coverage")


def box(ax, x, y, width, height, text, color="#E5EEF5", fontsize=10):
    ax.add_patch(FancyBboxPatch((x, y), width, height, boxstyle="round,pad=0.06,rounding_size=0.08",
                              facecolor=color, edgecolor="#526578", linewidth=1.2))
    ax.text(x + width / 2, y + height / 2, text, ha="center", va="center", fontsize=fontsize, linespacing=1.35)


def arrow(ax, start, end, label=None, bend=None, color="#526578", text_offset=(0, 0)):
    kwargs = {"connectionstyle": bend} if bend else {}
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=12,
                                linewidth=1.2, color=color, **kwargs))
    if label:
        ax.text((start[0] + end[0]) / 2 + text_offset[0], (start[1] + end[1]) / 2 + text_offset[1], label,
                ha="center", va="center", fontsize=9, color=color,
                bbox={"facecolor": "white", "edgecolor": "none", "pad": 1.5})


def draw_design(figures):
    fig, ax = plt.subplots(figsize=(12, 8.8))
    ax.set(xlim=(0, 12), ylim=(0, 9.4))
    ax.axis("off")
    ax.text(.1, 9.12, "Kernel module: work is selected at syscall entry", fontsize=15, fontweight="bold")
    ax.text(.1, 8.78, "Read top to bottom; follow labelled branches. Green = allow; teal = FSM slot; amber = log ring.", fontsize=9)
    box(ax, 3.7, 7.9, 4.6, .7, "open / openat / openat2 / read / write\nNative x86-64 syscall wrapper")
    box(ax, 3.7, 6.55, 4.6, .75, "sysmon_pre(): read one configuration snapshot\nCheck mode before decoding arguments")
    arrow(ax, (6, 7.9), (6, 7.3))
    box(ax, .2, 6.55, 2.4, .75, "OFF: return 0\nAllow syscall", "#EAF2E6")
    arrow(ax, (3.7, 6.93), (2.6, 6.93), "off", text_offset=(0, .16))
    box(ax, 3.7, 5.1, 4.6, .75, "Is this the collector's thread group?\nSkip its own device and file I/O")
    arrow(ax, (6, 6.55), (6, 5.85), "log / block", text_offset=(.65, 0))
    box(ax, 9.3, 5.1, 2.4, .75, "Return 0\nAllow syscall", "#EAF2E6")
    arrow(ax, (8.3, 5.48), (9.3, 5.48), "yes", text_offset=(0, .16))
    box(ax, 1.25, 3.45, 3.3, .9, "LOG: ignore block PID / operation\nOrdinary: capture all operations\nFSM: first match of current watch", fontsize=9)
    box(ax, 7.15, 3.45, 3.7, .9, "BLOCK\nCompare operation, then process ID\nNonmatch: allow without capture")
    arrow(ax, (4.8, 5.1), (2.9, 4.35), "no: log", text_offset=(-.20, .05))
    arrow(ax, (7.2, 5.1), (9.0, 4.35), "no: block", text_offset=(.2, .05))
    box(ax, 3.1, 1.82, 5.8, 1.0, "sysmon_capture(): monotonic + wall timestamps\nPID / TID, arguments, name, best-effort pathname\nOrdinary: ring record. FSM: independent pending match")
    arrow(ax, (2.9, 3.45), (4.3, 2.82), "selected entry", text_offset=(-.15, -.02))
    arrow(ax, (9.0, 3.45), (7.7, 2.82), "match: blocked event", text_offset=(.45, -.02))
    box(ax, .3, .20, 5.3, 1.0, "FSM notification mailbox: one retained match\nIndependent of ring capacity; never overwritten\nirq_work → POLLPRI → GET_MATCH\nOnly rearming / clearing releases the match", "#DEF2EF", fontsize=9)
    box(ax, 6.4, .20, 5.3, 1.0, "Normal log ring: 4096 entries\nFull ring: drop new entry and count loss\nirq_work → POLLIN → read() in batches\nA lost block log never cancels syscall denial", "#FFF1DC", fontsize=9)
    arrow(ax, (4.4, 1.82), (2.9, 1.2), "FSM match", text_offset=(-.25, .02))
    arrow(ax, (7.6, 1.82), (9.0, 1.2), "ordinary / blocked", text_offset=(.40, .02))
    ax.text(.2, -.12, "LOG always allows the syscall. A matching BLOCK skips its body with -EPERM. Neither path writes a file in kernel space.", fontsize=9)
    save_figure(fig, figures, "kernel_design")

    fig, ax = plt.subplots(figsize=(12, 7.4))
    ax.set(xlim=(0, 12), ylim=(0, 7.3))
    ax.axis("off")
    ax.text(.1, 7.0, "Userspace utility: control, receive, format, append", fontsize=15, fontweight="bold")
    ax.text(.1, 6.64, "Top row: configure left to right. Then follow the return arrow to the event-processing row.", fontsize=9)
    box(ax, .25, 5.4, 3.25, .95, "commands.c + fsm.c\nValidate flags and optional JSON\n--log --file: FSM; --once: one cycle", fontsize=9)
    box(ax, 4.4, 5.4, 3.0, .95, "main.c opens /dev/sysmon\nClaims collector if requested\nApplies ioctl configuration")
    box(ax, 8.4, 5.4, 3.3, .95, "Kernel control device\nNormal ring + separate match slot\nNo JSON or FSM state index", fontsize=9)
    arrow(ax, (3.5, 5.87), (4.4, 5.87))
    arrow(ax, (7.4, 5.87), (8.4, 5.87), "ioctl", text_offset=(0, .2))
    box(ax, .25, 3.55, 3.25, .95, "log.c waits using poll()\nread() or GET_MATCH notification\nReceive clock: after transfer", fontsize=9)
    box(ax, 4.4, 3.55, 3.0, .95, "Format UTC timestamps\nEscape text; render arguments\nPreserve kernel capture time")
    box(ax, 8.4, 3.55, 3.3, .95, "Append a line to sysmon.log\nfprintf() + fflush()\nAppend clock: after success")
    ax.plot([10, 10, 1.9], [5.34, 4.95, 4.95], color="#526578", linewidth=1.2)
    arrow(ax, (1.9, 4.95), (1.9, 4.5))
    ax.text(5.95, 5.08, "binary records", ha="center", fontsize=9, color="#526578")
    arrow(ax, (3.5, 4.03), (4.4, 4.03))
    arrow(ax, (7.4, 4.03), (8.4, 4.03))
    ax.text(.25, 2.93, "Red: blocked entries. Cyan: FSM transitions. Blank lines separate entries.", fontsize=10)
    ax.text(.25, 2.42, "Measurement timeline", fontsize=11, fontweight="bold")
    arrow(ax, (1.0, 1.52), (11.2, 1.52), color="#333333")
    for x, label in [(1.1, "Kernel capture\nCLOCK_MONOTONIC"), (6.0, "read() / GET_MATCH returns\nReceive timestamp"), (10.7, "Log write returns\nAppend timestamp")]:
        ax.plot([x, x], [1.4, 1.67], color="#333333")
        ax.text(x, 1.90, label, ha="center", va="bottom", fontsize=9)
    arrow(ax, (1.12, .94), (5.97, .94), "Reaction = receive − capture", color="#3978A8")
    arrow(ax, (1.12, .38), (10.67, .38), "End-to-end append delay = append − capture", color="#D58939")
    save_figure(fig, figures, "utility_design")

    # Illustrate the report's saved live example independently of the current
    # runtime configuration, which users may edit for subsequent experiments.
    states = ["open", "read", "write"]
    visible = [(i + 1, op) for i, op in enumerate(states)]
    fig, ax = plt.subplots(figsize=(12, 5.0))
    ax.set(xlim=(0, 12), ylim=(0, 5.0))
    ax.axis("off")
    ax.text(.2, 4.65, "Executed FSM example: open → read → write", fontsize=15, fontweight="bold")
    ax.text(.2, 4.15, "Read left to right: each arrow needs a fresh matching notification. Box numbers are JSON positions.", fontsize=10)
    step = 11.6 / len(visible)
    width = min(2.3, step - .5)
    centers = [.2 + step * (i + .5) for i in range(len(visible))]
    for center, (number, op) in zip(centers, visible):
        box(ax, center - width / 2, 2.75, width, .9,
            f"State {number}\nWait for {op}", fontsize=10)
    for i in range(len(visible) - 1):
        arrow(ax, (centers[i] + width / 2, 3.2), (centers[i + 1] - width / 2, 3.2))
    start, end = centers[0], centers[-1]
    ax.plot([end, end, start], [2.75, 1.9, 1.9], color="#526578", linewidth=1.2)
    arrow(ax, (start, 1.9), (start, 2.75))
    ax.text(6, 1.45, "After observing write: return to state 1. The executed --once run sets OFF and exits.", ha="center", fontsize=10)
    ax.text(.2, .8, "One cycle requires three accepted observations. Continuous mode would rearm open for the next cycle.", fontsize=10)
    ax.text(.2, .25, "Other operations and stale tokens leave the state unchanged. Calls before rearming are not replayed.", fontsize=10)
    save_figure(fig, figures, "fsm_design")

    fig, ax = plt.subplots(figsize=(12, 8.8))
    ax.set(xlim=(0, 12), ylim=(0, 9.2))
    ax.axis("off")
    ax.text(.1, 8.95, "Match notification protocol: kernel detects, userspace advances", fontsize=14, fontweight="bold")
    for x, label in [(.95, "Monitored\nprocess"), (4.15, "Kernel\nmatch slot"), (7.8, "Userspace\nFSM"), (11, "sysmon.log\nand console")]:
        box(ax, x - .85, 7.95, 1.7, .65, label, fontsize=9)
        ax.plot([x, x], [.9, 7.88], color="#bcc7d1", linestyle="--", linewidth=1)
    sequence = [
        (7.8, 4.15, 7.35, "SET_WATCH(expected op)"),
        (4.15, 7.8, 6.7, "fresh watch token"),
        (.95, 4.15, 6.05, "expected syscall entry"),
        (4.15, 7.8, 4.65, "POLLPRI wakeup"),
        (7.8, 4.15, 4.0, "GET_MATCH (non-consuming)"),
        (4.15, 7.8, 3.35, "token + timestamp + arguments"),
        (7.8, 11, 2.7, "append observation"),
        (7.8, 4.15, 2.05, "SET_WATCH(next op)"),
        (7.8, 11, 1.4, "report state transition"),
    ]
    for number, (start, end, y, label) in enumerate(sequence, 1):
        arrow(ax, (start, y), (end, y), f"{number}. {label}", text_offset=(0, .20))
    box(ax, 2.7, 5.03, 2.9, .5, "retain first match", "#DEF2EF", fontsize=9)
    ax.text(.1, .35, "Pending match survives normal-ring overflow and failed copies. Rearming or clearing acknowledges it.", fontsize=10)
    ax.text(.1, -.05, "Read steps 1–9 downward. Dashed lines identify participants; vertical spacing does not measure time.", fontsize=9)
    save_figure(fig, figures, "fsm_protocol")


def tex_escape(text):
    mapping = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#",
               "_": r"\_", "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}"}
    return "".join(mapping.get(char, char) for char in str(text))


def write_tex(summary, path):
    lines = ["% Generated by tests/plot_perf.py from measured data. Do not edit."]
    impact, latency, coverage, queue = [], [], [], []
    for name, item in summary["scenarios"].items():
        label = tex_escape(LABELS.get(name, name))
        macro = "".join(part.capitalize() for part in name.split("_"))
        if "transaction_us" in item:
            stats = item["transaction_us"]
            slowdown = f"{item['slowdown_pct']:+.1f}\\%" if "slowdown_pct" in item else "--"
            impact.append(f"{label} & {item['trials']} & {stats['median']:.2f} & "
                          f"{stats['min']:.2f}--{stats['max']:.2f} & {slowdown}" + r" \\")
            for suffix, value in [("MedianUs", stats["median"]), ("MinUs", stats["min"]), ("MaxUs", stats["max"]),
                                  ("SlowdownPct", item.get("slowdown_pct"))]:
                if value is not None:
                    lines.append(f"\\newcommand{{\\Perf{macro}{suffix}}}{{{value:.2f}}}")
        if name.startswith("latency_"):
            for field, stage in [("receive_us", "Receive"), ("append_us", "Append")]:
                stats = item[field]
                if stats:
                    latency.append(f"{label}: {stage.lower()} & {stats['n']} & {stats['median']:.2f} & {stats['p99']:.2f}" + r" \\")
                    for suffix, key in [("MedianUs", "median"), ("PNinetyNineUs", "p99")]:
                        lines.append(f"\\newcommand{{\\Perf{macro}{stage}{suffix}}}{{{stats[key]:.2f}}}")
        if item["expected_events"]:
            count = str(item["observed_events"]) if item["observed_events"] is not None else "missing"
            percent = f"{item['coverage_pct']:.1f}\\%" if item["coverage_pct"] is not None else "--"
            coverage.append(f"{label} & {count} & {item['expected_events']} & {percent}" + r" \\")
            if item["coverage_pct"] is not None:
                lines.append(f"\\newcommand{{\\Perf{macro}CoveragePct}}{{{item['coverage_pct']:.2f}}}")
        if "queue" in item:
            stats = item["queue"]
            average = f"{stats['mean_records_per_read']:.1f}" if stats["mean_records_per_read"] is not None else "--"
            queue.append(f"{label} & {stats['dropped']} & {stats['queue_high']} & {average}" + r" \\")
    if "baseline_drift_pct" in summary:
        lines.append(f"\\newcommand{{\\PerfBaselineDriftPct}}{{{summary['baseline_drift_pct']:.2f}}}")

    def table(name, layout, header, rows):
        body = "\n".join(rows) if rows else r"\multicolumn{" + str(len(layout)) + r"}{c}{No measurements available.} \\"
        heading = " & ".join(r"\tableheading{" + cell.strip() + "}" for cell in header.split(" & "))
        lines.extend([f"\\newcommand{{\\{name}}}{{%", r"\begingroup",
                      r"\rowcolors{2}{ReportStripe}{white}",
                      f"\\begin{{tabular}}{{{layout}}}", r"\toprule",
                      r"\rowcolor{ReportPale}" + heading + r" \\",
                      r"\midrule", body, r"\bottomrule", r"\end{tabular}\endgroup}"])

    table("PerfImpactTable", "lrrrr", r"Scenario & Trials & Median ($\mu$s) & Trial range ($\mu$s) & Change", impact)
    table("PerfLatencyTable", "lrrr", r"Scenario / endpoint & Events & Median ($\mu$s) & p99 ($\mu$s)", latency)
    table("PerfCoverageTable", "lrrr", "Scenario & Observed & Expected & Coverage", coverage)
    table("PerfQueueTable", "lrrr", "Scenario & Queue drops & Peak occupancy & Records/read", queue)
    notes = summary["notes"]
    if notes:
        # Combine identical-scenario loss warnings to keep the report readable.
        compact = []
        loss_scenarios = set()
        for note in notes:
            if "benchmark events; missing events" in note:
                scenario = note.split(" trial", 1)[0]
                if scenario in loss_scenarios:
                    continue
                loss_scenarios.add(scenario)
                compact.append(f"{scenario}: some benchmark events were absent from the log; missing events have unknown latency.")
            else:
                compact.append(note)
        lines.append(r"\newcommand{\PerfValidationNotes}{\begin{itemize}")
        lines.extend(r"\item " + tex_escape(note) for note in compact)
        lines.append(r"\end{itemize}}")
    else:
        lines.append(r"\newcommand{\PerfValidationNotes}{All selected records passed timing/count validation; no benchmark event loss was observed.}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    project = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, default=project / "results")
    parser.add_argument("--figures", type=Path, default=project / "figures")
    parser.add_argument("--design-only", action="store_true", help="draw architecture without measurement inputs")
    parser.add_argument("--report-tex", action="store_true",
                        help="also export results.tex for the report; normal analysis writes no LaTeX")
    args = parser.parse_args()
    args.figures.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "pdf.fonttype": 42, "ps.fonttype": 42})
    draw_design(args.figures)
    if args.design_only:
        print(f"Architecture figures written to {args.figures}")
        return 0
    try:
        trials = read_trials(args.results / "trials.csv")
        notes = []
        scenarios = load_events(args.results, trials, notes)
        summary = summarize(trials, scenarios, notes)
        (args.results / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        if args.report_tex:
            write_tex(summary, args.results / "results.tex")
        draw_impact(summary, args.figures)
        draw_latency(trials, args.figures)
        draw_coverage(summary, args.figures)
    except (OSError, ValueError, KeyError) as error:
        print(f"Performance input validation failed: {error}", file=sys.stderr)
        return 2
    for note in notes:
        print(f"Note: {note}", file=sys.stderr)
    print(f"Validated {len(trials)} trials. Summary: {args.results}; PDF/PNG figures: {args.figures}")
    if args.report_tex:
        print(f"Report LaTeX: {args.results / 'results.tex'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
