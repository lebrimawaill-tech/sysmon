#!/usr/bin/env python3
"""Capture real verification output and render labelled report excerpts.

No kernel is loaded and no privileged test is claimed to have run here.
Existing live results are copied verbatim and labelled as archived evidence.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import textwrap

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'tests/evidence'
ANSI = re.compile(r'\x1b\[[0-9;]*m')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_hashes():
    paths = []
    for directory in ('kmod', 'user', 'include', 'tests'):
        paths += list((ROOT / directory).glob('*.c'))
        paths += list((ROOT / directory).glob('*.h'))
        if (ROOT / directory / 'Makefile').exists():
            paths.append(ROOT / directory / 'Makefile')
    paths += [ROOT / 'tests/check_loads.py', ROOT / 'tests/plot_loads.py',
              ROOT / 'tests/analyze_timestamp_cache.py', ROOT / 'tests/perf_common.sh',
              ROOT / 'tests/report_evidence.py']
    return {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in sorted(paths)
            if not path.name.endswith('.mod.c') and not path.name.startswith('.')}


def capture_command(name, command):
    started = datetime.now(timezone.utc).isoformat()
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=120)
    path = EVIDENCE / f'{name}.txt'
    path.write_text(f'$ {shlex.join(command)}\nUTC: {started}\n\n'
                    + result.stdout + f'\nExit code: {result.returncode}\n')
    return {'command': command, 'utc': started, 'exit_code': result.returncode,
            'transcript': str(path.relative_to(ROOT)), 'sha256': sha(path.read_bytes())}


def save_archive(suite):
    candidates = sorted((ROOT / 'tests/results').glob(f'{suite}-cli-*/result.json'), reverse=True)
    for result_path in candidates:
        report = json.loads(result_path.read_text())
        directory = result_path.parent
        log = directory / 'sysmon.log'
        if not report.get('passed') or not log.exists():
            continue
        text = log.read_text()
        if suite == 'fsm':
            from test_cli_logs import validate_fsm
            states = json.loads((directory / 'fsm.json').read_text())['states']
            # Use the report's executed example, not a different saved sequence
            # or an older run that predates dedicated match delivery.
            if states != ['open', 'read', 'write'] or 'source=fsm_match' not in text:
                continue
            validate_fsm(text, states)
            assert report['transitions'] == len(states) and report['cycles'] == 1
            assert report['returned_to_state'] == 1
            names = ['result.json', 'fsm.json', 'sysmon.log', 'fsm.console.log']
            metadata = {'states': states, 'dedicated_channel': True}
        else:
            from test_cli_logs import validate_block
            denials = report['denials']
            assert [d['op'] for d in denials] == ['open', 'read', 'write']
            assert all(d['result'] == -1 and d['errno'] == 1 and d['side_effects'] == 0 for d in denials)
            validate_block(text, denials[0]['pid'], [d['op'] for d in denials])
            names = ['result.json', 'sysmon.log', 'open.console.log', 'read.console.log', 'write.console.log']
            metadata = {'denials': len(denials)}
        files = {}
        for name in names:
            original = directory / name
            target = EVIDENCE / f'archived_{suite}_{name.replace(".", "_")}.txt'
            target.write_bytes(original.read_bytes())
            files[name] = {'source': str(original.relative_to(ROOT)),
                           'copy': str(target.relative_to(ROOT)), 'sha256': sha(target.read_bytes())}
        return {'source_run': str(directory.relative_to(ROOT)), 'files': files, **metadata}
    return None


def render_capture(figures, name, title, subtitle, lines):
    rows = []
    for line in lines:
        color = '#8de4eb' if '\x1b[36m' in line else '#ffa0a0' if '\x1b[31m' in line else '#e7edf5'
        plain = ANSI.sub('', line.rstrip())
        rows.extend((part, color) for part in (textwrap.wrap(plain, 94, subsequent_indent='  ') or ['']))
    height = 1.5 + len(rows) * .23
    fig = plt.figure(figsize=(9.2, height), facecolor='#182333')
    fig.text(.025, 1 - .28 / height, title, color='white', weight='bold', size=14)
    fig.text(.025, 1 - .57 / height, textwrap.fill(subtitle, 110), color='#b7c8d8', size=8.8, va='top')
    for index, (line, color) in enumerate(rows):
        fig.text(.025, 1 - (1.16 + index * .23) / height, line,
                 family='DejaVu Sans Mono', size=11, color=color)
    for suffix in ('png', 'pdf'):
        fig.savefig(figures / f'{name}.{suffix}', dpi=170, facecolor=fig.get_facecolor(), bbox_inches='tight')
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--figures', type=Path, default=ROOT / 'tests/figures')
    parser.add_argument('--results', type=Path, default=ROOT / 'tests/results')
    parser.add_argument('--refresh', action='store_true', help='Rerun unprivileged checks and recopy archived evidence')
    args = parser.parse_args()
    args.figures.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(exist_ok=True)
    path = EVIDENCE / 'manifest.json'
    manifest = json.loads(path.read_text()) if path.exists() else {}
    hashes = source_hashes()
    if args.refresh or manifest.get('source_sha256') != hashes:
        manifest = {'captured_utc': datetime.now(timezone.utc).isoformat(),
                    'source_sha256': hashes, 'checks': {}}
        commands = {
            'build': ['make', 'kmod', 'user', 'tests'],
            'fsm': ['make', '-C', 'tests', 'check-fsm'],
            'timestamp': ['make', '-C', 'tests', 'check-timestamp'],
            'analysis': ['make', '-C', 'tests', 'check-performance'],
        }
        for name, command in commands.items():
            manifest['checks'][name] = capture_command(name, command)
            if manifest['checks'][name]['exit_code'] != 0:
                path.write_text(json.dumps(manifest, indent=2) + '\n')
                raise SystemExit(f'Check failed; inspect {manifest["checks"][name]["transcript"]}')
        manifest['archives'] = {suite: save_archive(suite) for suite in ('fsm', 'block')}
        if not manifest['archives']['fsm']:
            raise SystemExit('No passing live open/read/write FSM run with dedicated match delivery was found')
        path.write_text(json.dumps(manifest, indent=2) + '\n')
    for check in manifest['checks'].values():
        assert sha((ROOT / check['transcript']).read_bytes()) == check['sha256'], 'Evidence transcript changed'
    lines = []
    for name, check in manifest['checks'].items():
        raw = (ROOT / check['transcript']).read_text().splitlines()
        selected = [line for line in raw if line.startswith(('$ ', 'PASS:', 'Ran ', 'OK', 'Exit code:')) or
                    (line.startswith('test_') and line.endswith('... ok'))]
        lines += selected + ['']
    render_capture(args.figures, 'evidence_checks', 'Current-source verification: recorded command output',
                   'Unprivileged checks. Full transcripts and hashes: tests/evidence/manifest.json', lines)
    functional = args.results / 'block/functional.log'
    if (args.results / 'block/COMPLETE').is_file() and functional.is_file():
        raw = functional.read_text()
        if 'All sysmon integration checks passed.' not in raw:
            raise SystemExit('Host functional transcript has no successful completion verdict')
        # Standardize the report's terminology without modifying the saved log.
        display = re.sub(r'\bTGID\b', 'PID', raw)
        render_capture(args.figures, 'evidence_host_integration',
                       'Host kernel integration: recorded passing checks',
                       'Process identifiers labelled PID; original transcript retained. Source: ' + str(functional),
                       display.splitlines())
        manifest['host_integration'] = {
            'transcript': str(functional), 'sha256': sha(functional.read_bytes()),
            'scope': 'Saved privileged integration run inside the completed blocking suite',
        }
        path.write_text(json.dumps(manifest, indent=2) + '\n')
    for suite, archive in manifest['archives'].items():
        if not archive:
            continue
        for item in archive['files'].values():
            assert sha((ROOT / item['copy']).read_bytes()) == item['sha256'], 'Archived evidence copy changed'
        if suite == 'fsm':
            source = archive['files']['fsm.console.log']
            raw = (ROOT / source['copy']).read_text().splitlines()
            selected = [line for line in raw if 'FSM transition' in line or 'Loaded FSM' in line or
                        'Collection stopped:' in line or 'FSM completed' in line]
            subtitle = 'Open/read/write through dedicated match delivery; overflow retention not tested. Source: ' + archive['source_run'].split('/')[-1]
        else:
            selected = []
            for op in ('open', 'read', 'write'):
                raw = (ROOT / archive['files'][f'{op}.console.log']['copy']).read_text().splitlines()
                selected += [line for line in raw if line.startswith('Current mode:') or 'Observed syscall=' in line or
                             'Collection stopped:' in line] + ['']
            subtitle = 'Saved live run; sysmonctl-generated colored event output. Source: ' + archive['source_run'].split('/')[-1]
        result_lines = (ROOT / archive['files']['result.json']['copy']).read_text().splitlines()
        if suite == 'block':
            result_lines = [line for line in result_lines if any(f'"{key}"' in line for key in
                            ('passed', 'op', 'result', 'errno', 'side_effects'))]
        selected += ['', 'Selected verbatim lines from recorded result.json:', *result_lines]
        # Preserve JSON line boundaries before wrapping wide console lines.
        selected = '\n'.join(selected).splitlines()
        render_capture(args.figures, f'evidence_archived_{suite}', f'Saved live {suite} test: recorded result evidence', subtitle, selected)
    print(f'Verified transcripts and rendered captures: {args.figures}; provenance: {path}')


if __name__ == '__main__':
    main()
