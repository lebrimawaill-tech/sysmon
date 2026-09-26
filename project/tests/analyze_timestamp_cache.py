#!/usr/bin/env python3
"""Validate each live trial and summarize paired, trial-level differences."""
import csv
import argparse
import hashlib
import json
from pathlib import Path
import random
import statistics as st
import sys

import plot_loads as plots
from matplotlib.lines import Line2D
from matplotlib.ticker import MaxNLocator, PercentFormatter, ScalarFormatter


def draw(result, output):
    """Plot the measured pairs; keep this experiment separate from host sweeps."""
    output.mkdir(parents=True, exist_ok=True)
    rates = result['protocol']['rates']
    group_labels = plots.load_group_labels(rates)
    colors = {'baseline': '#0072B2', 'cached': '#D55E00'}
    summary_colors = {'baseline': '#8E44AD', 'cached': '#009E73'}
    samples = {(rate, variant): sorted(
        (t for t in result['trials'] if t['requested_rate'] == rate and t['variant'] == variant),
        key=lambda t: t['pair']) for rate in rates for variant in colors}
    legend = [Line2D([], [], marker='o', linestyle='none', color=palette[v],
                     label=f'{label}: {statistic}')
              for palette, statistic in [(colors, 'trials'), (summary_colors, 'median')]
              for v, label in [('baseline', 'Uncached'), ('cached', 'Cached')]]

    def pair_marks(ax, rate, field, left, right, divisor=1):
        baseline = [t[field] / divisor for t in samples[rate, 'baseline']]
        cached = [t[field] / divisor for t in samples[rate, 'cached']]
        for old, new in zip(baseline, cached):
            ax.plot([left, right], [old, new], color='#a9b4be', alpha=.7, lw=.9, zorder=1)
        for x, variant, values in [(left, 'baseline', baseline), (right, 'cached', cached)]:
            ax.scatter([x] * len(values), values, color=colors[variant], s=24, alpha=.7, zorder=2)
            ax.scatter(x, st.median(values), color=summary_colors[variant], marker='o', s=64,
                       edgecolor='#253442', linewidth=.9, zorder=3)
        return st.median(baseline), st.median(cached)

    def decorate(ax):
        ax.grid(axis='y', alpha=.22)
        ax.set_axisbelow(True)
        ax.spines[['top', 'right']].set_visible(False)

    def save(fig, name):
        for extension in ['pdf', 'png']:
            fig.savefig(output / f'{name}.{extension}', dpi=180, bbox_inches='tight')
        plots.plt.close(fig)

    with plots.plt.rc_context({'font.size': 11, 'axes.titlesize': 12, 'axes.labelsize': 11}):
        comparisons = {c['requested_rate']: c['metrics'] for c in result['comparisons']}
        row_colors = ['#0072B2', '#D55E00', '#009E73', '#8E44AD']
        effect_legend = [
            Line2D([], [], marker='o', linestyle='none', color='#697580', markersize=5,
                   label='One trial pair'),
            Line2D([], [], marker='o', linestyle='none', color='#697580', markersize=10,
                   markeredgecolor='#253442', label='Median paired change')]
        for field, title, name in [
                ('append_median_us', 'Median append latency', 'timestamp_median_change')]:
            fig, ax = plots.plt.subplots(figsize=(10, 4.8), layout='constrained')
            all_changes = []
            for index, rate in enumerate(rates):
                metric = comparisons[rate][field]
                changes = metric['paired_changes_pct']
                if len(changes) != result['protocol']['pairs']:
                    raise ValueError('Every latency pair must have a percentage change.')
                median = st.median(changes)
                color = row_colors[index % len(row_colors)]
                # Fixed vertical offsets expose overlapping pairs without changing x values.
                positions = [index + (i - (len(changes) - 1) / 2) * .08
                             + (-.12 if i < len(changes) / 2 else .12)
                             for i in range(len(changes))]
                ax.scatter(changes, positions, s=18, color=color, alpha=.8, zorder=3)
                ax.scatter(median, index, s=105, color=color, edgecolor='#253442',
                           linewidth=1.2, zorder=4)
                ax.text(1.025, index, f'{median:+.2f}%', transform=ax.get_yaxis_transform(),
                        va='center', color=color, fontsize=11, weight='bold')
                all_changes.extend(changes)
            low, high = min(0, min(all_changes)), max(0, max(all_changes))
            padding = max(2, (high - low) * .06)
            ax.set_xlim(low - padding, high + padding)
            ax.set_ylim(len(rates) - .55, -.65)
            ax.set_yticks(range(len(rates)), [group_labels[rate] for rate in rates])
            for label, color in zip(ax.get_yticklabels(), row_colors):
                label.set_color(color)
                label.set_weight('bold')
            ax.axvline(0, color='#4b5563', linewidth=1.2, zorder=2)
            ax.text(0, 1.015, 'No change', transform=ax.get_xaxis_transform(),
                    ha='center', fontsize=9, color='#4b5563')
            ax.text(1.025, 1.015, 'Median change', transform=ax.transAxes, fontsize=9)
            ax.xaxis.set_major_locator(MaxNLocator(nbins=8))
            ax.xaxis.set_major_formatter(PercentFormatter(xmax=100, decimals=0))
            ax.set_xlabel('Paired change (%)     ← lower latency     |     higher latency →')
            ax.set_title(title, loc='left', weight='bold', pad=28)
            decorate(ax)
            fig.suptitle('Effect of timestamp caching on append latency', fontsize=14, weight='bold')
            fig.legend(handles=effect_legend, loc='outside lower center', ncol=2, frameon=False)
            save(fig, name)

        fig, axes = plots.plt.subplots(1, 2, figsize=(10, 4.2), layout='constrained')
        labels = [group_labels[rate] for rate in rates]
        coverage_labels, rate_labels = [], []
        for index, rate in enumerate(rates):
            coverage = pair_marks(axes[0], rate, 'coverage_pct', index - .16, index + .16)
            achieved = pair_marks(axes[1], rate, 'achieved_rate_median', index - .16, index + .16, 1000)
            coverage_label = ' / '.join(f'{value:.2f}'.rstrip('0').rstrip('.') for value in coverage)
            coverage_labels.append(f'{labels[index]}\n{coverage_label}%')
            rate_labels.append(f'{labels[index]}\n{achieved[0]:.2f} / {achieved[1]:.2f}')
        for ax, tick_labels in zip(axes, [coverage_labels, rate_labels]):
            ax.set_xticks(range(len(rates)), tick_labels, fontsize=9)
            ax.set_xlabel('Recorded run group\nAxis values: uncached / cached medians', fontsize=9)
            ax.set_xlim(-.55, len(rates) - .4)
            decorate(ax)
        axes[0].set_title('Recorded workload events', loc='left', weight='bold')
        axes[0].set_ylabel('Event coverage (%)')
        axes[0].set_ylim(0, 114)
        axes[0].set_yticks([0, 25, 50, 75, 100])
        axes[1].set_title('Achieved producer rate', loc='left', weight='bold')
        axes[1].set_ylabel('Thousands of calls/s (log scale)')
        axes[1].set_yscale('log')
        axes[1].set_ylim(2, 1600)
        axes[1].set_yticks([3, 10, 30, 100, 1000])
        axes[1].yaxis.set_major_formatter(ScalarFormatter())
        fig.suptitle('Timestamp caching: coverage and offered load', fontsize=14, weight='bold')
        fig.legend(handles=legend, loc='outside lower center', ncol=2, frameon=False)
        save(fig, 'timestamp_delivery_load')

def bootstrap_median(values):
    rng = random.Random(20260926)
    samples = [st.median(rng.choices(values, k=len(values))) for _ in range(20000)]
    return [plots.percentile(samples, .025), plots.percentile(samples, .975)]

def write_tex(result, path):
    lines = ['% Generated from validated timestamp-cache comparison trials.']
    protocol = result['protocol']
    def macro(name, value):
        lines.append(r'\newcommand{\Cache' + name + '}{' + str(value) + '}')
    macro('Pairs', protocol['pairs'])
    macro('Trials', protocol['pairs'] * 2 * len(protocol['rates']))
    macro('DurationMs', protocol['duration_ms'])
    macro('MaxTransactions', f"{protocol['max_transactions']:,}")
    paced = sorted(rate for rate in protocol['rates'] if rate)
    if len(paced) != 3:
        raise ValueError('The report comparison requires three paced groups and an unpaced group.')
    prefixes = {0: 'Max', **dict(zip(paced, ['Low', 'Medium', 'High']))}
    for comparison in result['comparisons']:
        rate, metrics = comparison['requested_rate'], comparison['metrics']
        # TeX command names cannot contain digits; use names for cited loads.
        prefix = prefixes[rate]
        m = metrics['append_median_us']
        macro(prefix + 'MedianReductionPct', f"{-m['median_paired_change_pct']:.2f}")
        macro(prefix + 'MedianWins', m['cached_lower_pairs'])
        if rate == 0:
            for key, suffix in [('baseline_trial_median', 'Before'), ('cached_trial_median', 'After')]:
                macro('MaxCoverage' + suffix, f"{metrics['coverage_pct'][key]:.2f}")
                macro('MaxDrops' + suffix, f"{metrics['queue_drops'][key]:,.1f}")
    groups = plots.load_group_labels(protocol['rates'])
    indexed = {c['requested_rate']: c['metrics'] for c in result['comparisons']}
    lines.extend([
        r'\newcommand{\CacheAbsoluteLatencyTable}{\begingroup\small',
        r'\setlength{\tabcolsep}{5pt}',
        r'\begin{tabular}{llrr}\toprule',
        r'\rowcolor{ReportPale}Group & Unit & \multicolumn{2}{c}{Median append latency} \\',
        r'\rowcolor{ReportPale} & & Uncached & Cached \\\midrule'])
    for rate in protocol['rates']:
        metrics = indexed[rate]
        divisor, unit = (1000, 'ms') if rate == 0 else (1, r'\us{}')
        values = [metrics['append_median_us'][key] / divisor
                  for key in ['baseline_trial_median', 'cached_trial_median']]
        lines.append(' & '.join([groups[rate], unit, *(f'{value:.3f}' for value in values)]) + r' \\')
    lines.append(r'\bottomrule\end{tabular}\endgroup}')
    path.write_text('\n'.join(lines) + '\n')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, default=Path(__file__).resolve().parent / 'results/timestamp-cache-comparison')
    parser.add_argument('--report-tex', action='store_true',
                        help='also export results.tex for the report; normal analysis writes no LaTeX')
    args = parser.parse_args()
    output = args.results.resolve()
    if not (output / 'COMPLETE').exists():
        sys.exit('Live comparison has not completed.')
    protocol = json.loads((output / 'protocol.json').read_text())
    for variant in ['baseline', 'cached']:
        for name, expected in protocol['sha256'][variant].items():
            actual = hashlib.sha256((output / 'builds' / variant / name).read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(f'Experiment build fingerprint mismatch: {variant}/{name}')
    trials = []
    for pair in range(1, protocol['pairs'] + 1):
        for variant in ['baseline', 'cached']:
            directory = output / f'pair_{pair:02d}' / variant
            summary = plots.analyze(directory)
            if {g['requested_rate'] for g in summary['groups']} != set(protocol['rates']) or any(g['trials'] != 1 for g in summary['groups']):
                raise ValueError(f'Unexpected trial groups: {directory}')
            (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
            for group in summary['groups']:
                rate = group['requested_rate']
                run = directory / 'verbose' / f'rate_{rate}' / 'trial_1'
                workload = next(row for row in plots.rows(directory / 'trials.csv')
                                if int(row['requested_rate']) == rate)
                pid, start, end = (int(workload[key]) for key in ['pid', 'start_ns', 'end_ns'])
                postreceive = []
                with (run / 'metrics.csv').open() as stream:
                    for event in csv.DictReader(stream):
                        if int(event['pid']) == pid and start <= int(event['capture_mono_ns']) < end:
                            postreceive.append((int(event['append_mono_ns']) - int(event['receive_mono_ns'])) / 1000)
                group['postreceive_median_us'] = plots.percentile(postreceive, .5)
                trials.append(dict(pair=pair, variant=variant, **group))
    metrics = ['append_median_us', 'receive_median_us', 'postreceive_median_us',
               'coverage_pct', 'achieved_rate_median', 'queue_drops']
    comparisons = []
    for rate in protocol['rates']:
        b = sorted([t for t in trials if t['requested_rate'] == rate and t['variant'] == 'baseline'], key=lambda t: t['pair'])
        c = sorted([t for t in trials if t['requested_rate'] == rate and t['variant'] == 'cached'], key=lambda t: t['pair'])
        comparison = {'requested_rate': rate, 'pairs': len(b), 'metrics': {}}
        for metric in metrics:
            baseline, cached = [t[metric] for t in b], [t[metric] for t in c]
            deltas = [100 * (new / old - 1) for old, new in zip(baseline, cached) if old]
            comparison['metrics'][metric] = {
                'baseline_trial_median': st.median(baseline),
                'cached_trial_median': st.median(cached),
                'baseline_range': [min(baseline), max(baseline)],
                'cached_range': [min(cached), max(cached)],
                'paired_changes_pct': deltas,
                'median_paired_change_pct': st.median(deltas) if deltas else None,
                'median_change_ci95_pct': bootstrap_median(deltas) if deltas else None,
                'cached_lower_pairs': sum(new < old for old, new in zip(baseline, cached)),
            }
        comparisons.append(comparison)
    result = {'protocol': protocol, 'notes': [
        'Every input is validated with the existing plot_loads.analyze checks.',
        'Summaries are medians of trial quantiles; paired bootstrap resamples eight trial pairs, not individual records.',
        'Confidence intervals are exploratory and unadjusted for multiple metrics/loads.',
        'Negative paired percentage changes mean smaller values, favorable for latency but unfavorable for coverage.',
        'Receive-to-append includes preceding records in the read batch and is not isolated timestamp-formatting time.'
    ], 'comparisons': comparisons, 'trials': trials}
    (output / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    if args.report_tex:
        write_tex(result, output / 'results.tex')
    draw(result, output / 'figures')
    print('rate metric baseline cached paired_change_pct lower_pairs CI95')
    for c in comparisons:
        for metric in metrics:
            m = c['metrics'][metric]
            print(c['requested_rate'], metric, round(m['baseline_trial_median'], 3),
                  round(m['cached_trial_median'], 3), m['median_paired_change_pct'],
                  m['cached_lower_pairs'], m['median_change_ci95_pct'])

if __name__ == '__main__':
    main()
