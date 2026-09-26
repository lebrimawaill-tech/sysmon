#!/usr/bin/env python3
"""Plot direct latency, impact, and blocking runs; never invent missing results.

python3 tests/plot_loads.py --results tests/results/latency
python3 tests/plot_loads.py --results tests/results   # every completed suite
"""
import argparse
import csv
import json
import math
from pathlib import Path
import re
import statistics as st
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import EngFormatter, FixedLocator, NullFormatter

ORDER = ["baseline", "off", "block_miss", "verbose", "baseline_after"]
LABEL = {"baseline": "Module absent", "off": "Off", "block_miss": "Block: no match",
         "verbose": "Log: console", "baseline_after": "Absent: recheck"}
COLOR = dict(zip(ORDER, ["#666666", "#279e8e", "#8b7d37", "#d67822", "#9c65a7"]))
HEADER = re.compile(r"\bmono_ns=(\d+) seq=(\d+) pid=(\d+) tid=(\d+) ")


def rows(path):
    with path.open(newline="", encoding="utf8") as stream:
        return list(csv.DictReader(stream))


def percentile(values, p):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * p
    a, b = math.floor(position), math.ceil(position)
    return values[a] + (values[b] - values[a]) * (position - a)


def selected_events(path, pid, start, end):
    selected = set()
    seen = set()
    with path.open(encoding="utf8") as stream:
        for number, line in enumerate(stream, 1):
            # The collector separates real records with blank lines.
            if not line.strip():
                continue
            match = HEADER.search(line)
            if not match:
                raise ValueError(f"{path}:{number}: malformed log record")
            capture, sequence, record_pid, _ = map(int, match.groups())
            if sequence in seen:
                raise ValueError(f"{path}: duplicate sequence {sequence}")
            seen.add(sequence)
            if record_pid == pid and start <= capture < end:
                selected.add(sequence)
    return selected


def analyze(root):
    if not (root / "COMPLETE").is_file():
        raise ValueError(f"{root}: no COMPLETE marker; run did not finish successfully")
    trials = rows(root / "trials.csv")
    if not trials:
        raise ValueError(f"{root}: no trials")
    if "operation" not in trials[0] and "suite" not in trials[0]:
        raise ValueError("this is an archived run; use plot_perf.py, or provide a new latency/impact/block result directory")
    suite = "block" if "operation" in trials[0] else trials[0]["suite"]
    if suite not in ("latency", "impact", "block"):
        raise ValueError(f"{root}: unsupported suite {suite}")
    # Include only scenarios supported by the current suite when reading archives.
    allowed = ("open", "read", "write") if suite == "block" else ("verbose",) if suite == "latency" else ORDER
    trials = [row for row in trials if row.get("operation", row.get("scenario")) in allowed]
    if not trials:
        raise ValueError(f"{root}: no supported trials")
    groups, seen = {}, set()
    for row in trials:
        scenario = row.get("operation", row.get("scenario"))
        if not re.fullmatch(r"[a-z_]+", scenario or ""):
            raise ValueError("invalid scenario")
        rate, trial = int(row["requested_rate"]), int(row["trial"])
        key = (scenario, rate, trial)
        if key in seen or rate < 0 or trial <= 0:
            raise ValueError(f"duplicate/invalid trial {key}")
        seen.add(key)
        if int(row["errors"]):
            raise ValueError(f"{key}: workload errors; timing would be misleading")
        achieved = float(row["achieved_rate"])
        if not math.isfinite(achieved) or achieved <= 0:
            raise ValueError(f"{key}: invalid achieved rate")
        group = groups.setdefault((scenario, rate), {"scenario": scenario, "requested_rate": rate,
            "trials": 0, "achieved_rates": [], "service_means_us": [],
            "receive_us": [], "append_us": [], "expected_events": 0, "logged_events": 0,
            "attempts": 0, "denied": 0, "queue_drops": 0, "missed_slots": 0})
        group["trials"] += 1
        group["achieved_rates"].append(achieved)
        if suite == "block":
            attempts, denied, allowed = (int(row[k]) for k in ("attempts", "denied", "allowed"))
            logged, drops = int(row["blocked_records"]), int(row["queue_drops"])
            if (attempts <= 0 or denied != attempts or allowed or int(row["side_effects"]) or
                    logged < 0 or drops < 0 or logged + drops != denied):
                raise ValueError(f"{key}: blocking failed or denial accounting is inconsistent")
            group["attempts"] += attempts
            group["denied"] += denied
            group["logged_events"] += logged
            group["queue_drops"] += drops
            continue
        if row["suite"] != suite:
            raise ValueError("mixed suite CSV")
        start, end, pid = (int(row[k]) for k in ("start_ns", "end_ns", "pid"))
        count = int(row["transactions"])
        if count <= 0 or pid <= 0 or start <= 0 or end <= start or end - start != int(row["elapsed_ns"]):
            raise ValueError(f"{key}: invalid capture interval/count")
        if abs(achieved - 3e9 * count / (end - start)) > .002:
            raise ValueError(f"{key}: achieved rate disagrees with timing/counts")
        group["missed_slots"] += int(row["missed_slots"])
        if suite == "impact":
            mean = float(row["service_mean_ns"])
            p50, p99 = (int(row[k]) for k in ("response_p50_ns", "response_p99_ns"))
            if not math.isfinite(mean) or mean <= 0 or not 0 <= p50 <= p99:
                raise ValueError(f"{key}: invalid response times")
            group["service_means_us"].append(mean / 1000)
        if scenario != "verbose":
            continue
        run = root / scenario / f"rate_{rate}" / f"trial_{trial}"
        sequences = selected_events(run / "sysmon.log", pid, start, end)
        if len(sequences) > 3 * count:
            raise ValueError(f"{key}: more records than syscall attempts")
        group["expected_events"] += 3 * count
        group["logged_events"] += len(sequences)
        before, after = rows(run / "before.stats"), rows(run / "after.stats")
        if len(before) != 1 or len(after) != 1:
            raise ValueError(f"{run}: invalid stats snapshot")
        drop_delta = int(after[0]["dropped"]) - int(before[0]["dropped"])
        if drop_delta < 0:
            raise ValueError(f"{run}: drop counter decreased")
        group["queue_drops"] += drop_delta
        if suite == "latency":
            measured = set()
            for event in rows(run / "metrics.csv"):
                capture = int(event["capture_mono_ns"])
                if int(event["pid"]) != pid or not start <= capture < end:
                    continue
                sequence = int(event["seq"])
                receive, append = int(event["receive_mono_ns"]), int(event["append_mono_ns"])
                if sequence in measured or not capture <= receive <= append:
                    raise ValueError(f"{run}: duplicate event or negative latency")
                measured.add(sequence)
                group["receive_us"].append((receive - capture) / 1000)
                group["append_us"].append((append - capture) / 1000)
            if measured != sequences:
                raise ValueError(f"{run}: metrics/log event identities disagree")
    summary = {"suite": suite, "notes": [
        "Requested rates are monitored syscall attempts/s; rate 0 is unpaced maximum.",
        "Impact times exclude pacing sleeps and include the same clock overhead in each mode.",
        "Latency distributions describe delivered events; missing events have unknown latency.",
        "Each collector is restarted and drained between trials. Console output goes to a regular file."
    ], "groups": []}
    for group in groups.values():
        for source, prefix in (("receive_us", "receive"), ("append_us", "append")):
            values = group.pop(source)
            for name, p in (("median", .5), ("p99", .99)):
                group[f"{prefix}_{name}_us"] = percentile(values, p)
        group["achieved_rate_median"] = st.median(group["achieved_rates"])
        denominator = group["expected_events"] or group["attempts"]
        group["coverage_pct"] = 100 * group["logged_events"] / denominator if denominator else None
        if group["service_means_us"]:
            group["service_mean_median_us"] = st.median(group["service_means_us"])
            baseline = groups.get(("baseline", group["requested_rate"]))
            group["slowdown_pct"] = (100 * (group["service_mean_median_us"] / st.median(baseline["service_means_us"]) - 1)
                                      if baseline else None)
        summary["groups"].append(group)
    return summary


def load_group_labels(rates):
    """Name saved run groups without rewriting their original pacing metadata."""
    paced = sorted(rate for rate in rates if rate)
    names = ['Low', 'Medium', 'High'] if len(paced) == 3 else [f'Paced {i + 1}' for i in range(len(paced))]
    return {0: 'Unpaced', **dict(zip(paced, names))}


def measured_ticks(ax, values):
    """Stack nearby rate labels, retaining a minor tick at every actual rate."""
    clusters = []
    for value in sorted(set(values)):
        if not clusters or value / clusters[-1][0] > 1.22:
            clusters.append([])
        clusters[-1].append(value)
    positions = [math.exp(st.mean(math.log(v) for v in cluster)) for cluster in clusters]
    labels = ['\n'.join(dict.fromkeys(f'{v:,.0f}' for v in cluster)) for cluster in clusters]
    ax.set_xticks(positions, labels, fontsize=8)
    ax.xaxis.set_minor_locator(FixedLocator(sorted(set(values))))
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.tick_params(axis='x', which='minor', length=3)


def label_values(ax, points, formatter):
    """Place summary values beside their markers, spreading crowded labels."""
    # Work in display coordinates so spacing also works on logarithmic axes.
    groups = []
    for x, y, color in sorted(points, key=lambda p: p[0]):
        if y is None or not math.isfinite(y):
            continue
        px, py = ax.transData.transform((x, y))
        if not groups or px - groups[-1][0][0] > 42:
            groups.append([])
        groups[-1].append((px, py, x, y, color))
    gap = 12 * ax.figure.dpi / 72
    for group in groups:
        group.sort(key=lambda p: p[1])
        heights = []
        for _, py, *_ in group:
            heights.append(max(py, heights[-1] + gap if heights else ax.bbox.y0 + gap / 2))
        shift = max(0, heights[-1] - ax.bbox.y1 + gap / 2)
        for (px, py, x, y, color), height in zip(group, heights):
            right = px < ax.bbox.x1 - 65
            dx = 7 if right else -7
            ax.annotate(formatter(y), (x, y), xytext=(dx, (height - shift - py) * 72 / ax.figure.dpi),
                        textcoords='offset points', ha='left' if right else 'right', va='center',
                        color=color, fontsize=8, annotation_clip=False,
                        bbox=dict(facecolor='white', edgecolor='none', alpha=.85, pad=.35),
                        arrowprops=dict(arrowstyle='-', color=color, alpha=.55, lw=.6),
                        zorder=5).set_in_layout(False)


def draw(summary, output):
    suite, groups = summary["suite"], summary["groups"]
    rates = sorted({g["requested_rate"] for g in groups}, key=lambda r: (r == 0, r))
    scenarios = sorted({g["scenario"] for g in groups},
                       key=lambda s: (ORDER.index(s) if s in ORDER else 99, s))
    group_labels = load_group_labels(rates)
    labels = [group_labels[rate] for rate in rates]
    value_labels = {}

    def decorate(ax, measured=False):
        if measured:
            ax.set_xscale("log")
            ax.set_xlabel("Measured producer rate (calls/s; log scale)")
            ax.tick_params(axis="x", labelsize=10)
        else:
            ax.set_xticks(range(len(rates)), labels, fontsize=10)
            ax.set_xlabel("Recorded run group")
        ax.grid(axis="y", alpha=.22)
        ax.set_axisbelow(True)
        ax.spines[["top", "right"]].set_visible(False)

    if suite == "block":
        # Flat 100% denial/coverage curves repeated the same visual three times.
        # State those measured checks once and graph the varying achieved rates.
        fig, ax = plt.subplots(figsize=(10, 5.3), layout="constrained")
        for index, scenario in enumerate(scenarios):
            selected = {g["requested_rate"]: g for g in groups if g["scenario"] == scenario}
            color = ["#346b95", "#d67822", "#168275"][index % 3]
            offset = (index - (len(scenarios) - 1) / 2) * .14
            positions = [i + offset for i in range(len(rates))]
            values = [selected.get(rate, {}).get("achieved_rate_median", math.nan) for rate in rates]
            ax.plot(positions, values, marker="o", color=color,
                    label=scenario, lw=1.4)
            value_labels.setdefault(ax, []).extend((x, y, color) for x, y in zip(positions, values))
            for position, rate in zip(positions, rates):
                samples = selected.get(rate, {}).get("achieved_rates", [])
                if samples:
                    ax.vlines(position, min(samples), max(samples), color=color, alpha=.65)
                    ax.scatter([position] * len(samples), samples, s=20, color=color, alpha=.55)
        attempts = sum(g["attempts"] for g in groups)
        denied = sum(g["denied"] for g in groups)
        logged = sum(g["logged_events"] for g in groups)
        drops = sum(g["queue_drops"] for g in groups)
        fig.suptitle("Blocking: achieved attempt rate\n"
                     f"{denied:,}/{attempts:,} attempts denied; {logged:,} records delivered; {drops:,} ring drops",
                     fontsize=13)
        ax.set_yscale("log")
        ax.set_ylabel("Achieved attempts/s (log scale)")
        ax.yaxis.set_major_formatter(EngFormatter())
        ax.legend(fontsize=10, frameon=False, loc='upper left')
        decorate(ax)
    else:
        fig = plt.figure(figsize=(11, 9), layout="constrained")
        grid = fig.add_gridspec(2, 2, height_ratios=[1.15, 1])
        timing = fig.add_subplot(grid[0, :])
        coverage = fig.add_subplot(grid[1, 0])
        load = fig.add_subplot(grid[1, 1])
        decorate(timing, measured=True)
        decorate(coverage, measured=True)
        decorate(load)
        for index, scenario in enumerate(scenarios):
            color = COLOR.get(scenario, ["#346b95", "#d67822", "#168275"][index % 3])
            label = LABEL.get(scenario, scenario)
            selected = {g["requested_rate"]: g for g in groups if g["scenario"] == scenario}

            def series(field):
                return [selected.get(rate, {}).get(field, math.nan) for rate in rates]

            def line(ax, field, name, line_color=color, style="-", marker="o"):
                values = series(field)
                if any(v is not None and math.isfinite(v) for v in values):
                    positions = range(len(rates)) if ax is load else series("achieved_rate_median")
                    ax.plot(positions, values, style, marker=marker, markersize=5,
                            color=line_color, label=name)
                    value_labels.setdefault(ax, []).extend((x, y, line_color) for x, y in zip(positions, values))

            if suite == "latency":
                for field, name, line_color in [
                        ("receive_median_us", "Receive median", "#0072B2"),
                        ("append_median_us", "Append median", "#009E73")]:
                    line(timing, field, name, line_color)
            else:
                line(timing, "service_mean_median_us", label)
                for rate in rates:
                    samples = selected.get(rate, {}).get("service_means_us", [])
                    if samples:
                        position = selected[rate]["achieved_rate_median"]
                        timing.vlines(position, min(samples), max(samples), color=color, alpha=.6)
            line(coverage, "coverage_pct", label, "#A87900" if suite == "latency" else color)
            line(load, "achieved_rate_median", label, "#4B5563" if suite == "latency" else color)
        for ax, measured_values in [
                (timing, [g["achieved_rate_median"] for g in groups]),
                (coverage, [g["achieved_rate_median"] for g in groups if g["coverage_pct"] is not None])]:
            if measured_values:
                ax.set_xlim(min(measured_values) * .8, max(measured_values) * 1.2)
                measured_ticks(ax, measured_values)
                if ax is coverage:
                    plt.setp(ax.get_xticklabels(), rotation=30, ha='right')
        if suite == "latency":
            timing.set_title("Receipt and append delay on the same scale", fontsize=12, loc="left", weight="bold")
            timing.set_ylabel("Latency (µs; delivered events)")
            timing.set_yscale("symlog", linthresh=1)
            timing.set_ylim(bottom=0)
            title = "Initial host latency sweep (before timestamp caching)"
        else:
            timing.set_title("Transaction response: median of trial means and trial range", fontsize=12, loc="left", weight="bold")
            timing.set_ylabel("Mean transaction time (µs)")
            title = "Initial host impact sweep: useful work, excluding pacing sleep"
        coverage.set_title("Recorded workload events", fontsize=12, loc="left", weight="bold")
        coverage.set_ylabel("Coverage (%)")
        coverage.set_ylim(0, 105)
        load.set_title("Measured producer rate by run group", fontsize=12, loc="left", weight="bold")
        load.set_ylabel("Actually achieved syscalls/s")
        load.set_yscale('log')
        load.yaxis.set_major_formatter(EngFormatter())
        for ax in [timing, coverage, load]:
            if ax.get_legend_handles_labels()[0]:
                ax.legend(fontsize=8 if ax is load else 9, loc="best",
                          ncol=2 if ax in (timing, load) else 1, frameon=False)
        fig.suptitle(title, fontsize=13)
    fig.canvas.draw()
    for ax, points in value_labels.items():
        is_rate = suite == 'block' or ax is load
        label_values(ax, points, (lambda v: f'{v:,.0f}') if is_rate else (lambda v: f'{v:.2f}'))
    output.mkdir(parents=True, exist_ok=True)
    for extension in ("png", "pdf"):
        fig.savefig(output / f"{suite}_vs_load.{extension}", dpi=180)
    plt.close(fig)



def write_tex(summary, path):
    """Export the validated host summaries used by report.tex."""
    suite, groups = summary["suite"], summary["groups"]
    lines = ["% Generated from validated direct-test measurements by plot_loads.py."]
    indexed = {(g["scenario"], g["requested_rate"]): g for g in groups}

    def macro(name, value):
        lines.append(r"\newcommand{\Host" + name + "}{" + str(value) + "}")

    def table(name, columns, headers, data):
        lines.extend([r"\newcommand{\Host" + name + r"}{\begingroup\footnotesize",
                      r"\setlength{\tabcolsep}{4pt}\rowcolors{2}{ReportStripe}{white}",
                      r"\begin{tabular}{" + columns + r"}\toprule\rowcolor{ReportPale}",
                      " & ".join(r"\tableheading{" + h + "}" for h in headers) + r" \\\midrule"])
        lines.extend(" & ".join(row) + r" \\" for row in data)
        lines.append(r"\bottomrule\end{tabular}\endgroup}")

    macro(suite.capitalize() + "Trials", sum(g["trials"] for g in groups))
    if suite == "latency":
        data = []
        group_labels = load_group_labels({g['requested_rate'] for g in groups})
        for g in groups:
            data.append(["Console",
                         group_labels[g["requested_rate"]],
                         f'{g["achieved_rate_median"]:,.0f}',
                         f'{g["receive_median_us"]:.2f}',
                         f'{g["append_median_us"]:.2f}', f'{g["coverage_pct"]:.2f}\\%'])
        table("LatencyTable", "llrrrr", ["Mode", "Run", "Produced/s", "Receive", "Append", "Coverage"], data)
        for scenario, name in [("verbose", "Verbose")]:
            for rate, suffix in [(3000, "Paced"), (0, "Max")]:
                g = indexed.get((scenario, rate))
                if g:
                    for key, field in [("ReceiveUs", "receive_median_us"), ("AppendUs", "append_median_us"), ("CoveragePct", "coverage_pct")]:
                        macro(name + suffix + key, f'{g[field]:.2f}')
    elif suite == "impact":
        data = []
        for scenario in ORDER:
            g = indexed.get((scenario, 0))
            if not g:
                continue
            data.append([LABEL[scenario], f'{g["service_mean_median_us"]:.3f}',
                         f'{min(g["service_means_us"]):.3f}--{max(g["service_means_us"]):.3f}',
                         f'{g["slowdown_pct"]:+.2f}\\%' if g["slowdown_pct"] is not None else "--",
                         f'{g["coverage_pct"]:.2f}\\%' if g["coverage_pct"] is not None else "--"])
            name = {"baseline": "Baseline", "off": "Off", "block_miss": "BlockMiss", "verbose": "Verbose", "baseline_after": "Recheck"}[scenario]
            macro(name + "ResponseUs", f'{g["service_mean_median_us"]:.3f}')
            if g["slowdown_pct"] is not None:
                macro(name + "ChangePct", f'{g["slowdown_pct"]:.2f}')
        table("ImpactTable", "lrrrr", ["Unpaced scenario", "Mean time", "Trial range", "Change", "Coverage"], data)
    else:
        data = []
        for op in ("open", "read", "write"):
            selected = [g for g in groups if g["scenario"] == op]
            if not selected:
                continue
            data.append([op, str(sum(g["trials"] for g in selected)),
                         f'{sum(g["attempts"] for g in selected):,}',
                         f'{sum(g["denied"] for g in selected):,}',
                         f'{sum(g["queue_drops"] for g in selected):,}'])
        table("BlockTable", "lrrrr", ["Operation", "Trials", "Attempts", "EPERM", "Log drops"], data)
        macro("BlockAttempts", f'{sum(g["attempts"] for g in groups):,}')
        macro("BlockDrops", sum(g["queue_drops"] for g in groups))
    path.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path(__file__).resolve().parent / "results")
    parser.add_argument("--report-tex", action="store_true",
                        help="also export results.tex for the report; normal analysis writes no LaTeX")
    args = parser.parse_args()
    roots = [args.results / s for s in ("latency", "impact", "block") if (args.results / s / "trials.csv").is_file()]
    if not roots:
        roots = [args.results]
    try:
        for root in roots:
            summary = analyze(root)
            draw(summary, root / "figures")
            if args.report_tex:
                write_tex(summary, root / "results.tex")
            (root / "summary.json").write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
            print(f"{summary['suite']}: validated {len(summary['groups'])} rate/condition groups; figures at {root / 'figures'}")
    except (OSError, ValueError, KeyError, ZeroDivisionError) as error:
        print(f"Cannot plot performance data: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
