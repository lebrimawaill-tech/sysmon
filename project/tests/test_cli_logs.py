#!/usr/bin/env python3
"""Live CLI tests: sysmonctl alone controls the module and writes sysmon.log."""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
CTL = ROOT / "user/sysmonctl"
WORKER = ROOT / "tests/syscall_worker"
RED, CYAN, RESET = "\x1b[31m", "\x1b[36m", "\x1b[0m"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_text(path):
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def fields(line):
    return dict(re.findall(r"\b([a-z_]+)=([^ \n\x1b]+)", line))


def validate_fsm(text, states):
    transitions = [line for line in text.splitlines() if "FSM transition " in line]
    observations = {fields(line)["seq"]: fields(line) for line in text.splitlines()
                    if line.startswith("captured=")}
    require(len(transitions) == len(states),
            f"FSM observed {len(transitions)}/{len(states)} states; a complete JSON cycle is required")
    for index, line in enumerate(transitions):
        data = fields(line)
        next_index = (index + 1) % len(states)
        final = index == len(states) - 1
        require(line.startswith(CYAN) and line.endswith(RESET), "FSM transition is not cyan")
        require(data["observed"] == states[index] and
                data["from"] == f"{index + 1}({states[index]})" and
                data["current_state"] == f"{next_index + 1}/{len(states)}" and
                data["expected"] == states[next_index], "FSM transition differs from JSON")
        require(data["cycles"] == ("1" if final else "0") and
                data["mode"] == ("off" if final else "log"), "FSM stopped at the wrong state")
        observation = observations.get(data["seq"])
        require(observation is not None and observation["operation"] == states[index] and
                observation.get("source") == "fsm_match" and
                observation["blocked"] == "no" and
                observation["capture_ns"] == data["captured_ns"],
                "Transition has no corresponding actual observation")
        require(int(data["logged_ns"]) > 0, "Missing FSM logging timestamp")
    require(len(observations) == len(states), "FSM logged observations beyond the first cycle")
    return len(transitions)


def validate_block(text, pid, operations):
    lines = [line for line in text.splitlines() if "blocked=yes" in line]
    require(len(lines) == len(operations), "Missing or extra blocked events")
    for line, operation in zip(lines, operations):
        data = fields(line)
        require(line.startswith(RED) and line.endswith(RESET), "Blocked entry is not red")
        require(data["pid"] == str(pid) and data["operation"] == operation,
                "Blocked entry has the wrong process or operation")
        require(int(data["capture_ns"]) > 0 and int(data["append_ns"]) > 0,
                "Blocked entry lacks capture/append timestamps")


class LiveTest:
    def __init__(self, args, output):
        self.args, self.output = args, output
        self.loaded = False
        self.prepared = False
        self.worker = self.collector = self.channel = None
        self.console = None

    def ctl(self, *args):
        result = subprocess.run([str(CTL), *args], cwd=self.output,
                                capture_output=True, text=True, timeout=5)
        require(result.returncode == 0, f"sysmonctl {' '.join(args)}: {result.stderr}")
        return result.stdout

    def prepare(self):
        if Path('/sys/module/sysmon').exists():
            require(self.args.use_loaded, "sysmon is already loaded: unload it first or use --use-loaded")
        else:
            require(not self.args.use_loaded, "--use-loaded requires an already loaded module")
            subprocess.run(['insmod', str(ROOT / 'kmod/sysmon.ko')], check=True, timeout=10)
            self.loaded = True
        deadline = time.monotonic() + 5
        while not Path('/dev/sysmon').exists() and time.monotonic() < deadline:
            time.sleep(.01)
        require("Current mode: off\n" in self.ctl('--status'), "Module must initially be off")
        self.prepared = True
        self.channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.channel.settimeout(3)
        try:
            self.worker = subprocess.Popen([str(WORKER), str(child.fileno()),
                                            str(self.output / 'payload')], pass_fds=(child.fileno(),))
        finally:
            child.close()
        require(self.channel.recv(1024) == b'ready', "Syscall worker failed to initialize")

    def action(self, operation):
        self.channel.sendall(operation.encode())
        return json.loads(self.channel.recv(1024))

    def start(self, name, *args):
        self.console_path = self.output / f'{name}.console.log'
        self.console = self.console_path.open('w')
        self.collector = subprocess.Popen([str(CTL), *args], cwd=self.output,
                                          stdout=self.console, stderr=subprocess.STDOUT)

    def wait_for(self, condition):
        deadline = time.monotonic() + self.args.timeout
        while not condition():
            require(self.collector.poll() is None,
                    f"Collector exited unexpectedly: {read_text(self.console_path)}")
            require(time.monotonic() < deadline, f"Timed out; see {self.console_path}")
            time.sleep(.01)

    def stop(self):
        self.ctl('--off')
        if self.collector.poll() is None:
            self.collector.send_signal(signal.SIGTERM)
        require(self.collector.wait(timeout=5) == 0, f"Collector failed: {self.console_path}")
        self.collector = None
        self.console.close()
        self.console = None

    def fsm(self, states):
        self.start('fsm', '--log', '--file', str(self.output / 'fsm.json'), '--once')
        deadline = time.monotonic() + self.args.timeout
        while self.collector.poll() is None:
            text = read_text(self.output / 'sysmon.log')
            require(time.monotonic() < deadline, f"FSM timeout; see {self.console_path}")
            if 'FSM start ' in text:
                count = sum('FSM transition ' in line for line in text.splitlines())
                if count < len(states):
                    result = self.action(states[count])
                    require(result['result'] >= 0, f"FSM syscall failed: {result}")
            time.sleep(.01)
        require(self.collector.returncode == 0, f"FSM failed: {read_text(self.console_path)}")
        count = validate_fsm(read_text(self.output / 'sysmon.log'), states)
        require('FSM completed one cycle' in read_text(self.console_path), "Missing completion message")
        require('Current mode: off\n' in self.ctl('--status'), "FSM left monitoring enabled")
        self.stop()
        print(f'FSM: {count}/{len(states)} states observed, including state {len(states)}; returned to state 1.\n',
              flush=True)
        return {'transitions': count, 'returned_to_state': 1, 'cycles': 1, 'color': 'cyan'}

    def block(self):
        operations, replies = ['open', 'read', 'write'], []
        for index, operation in enumerate(operations):
            self.start(operation, '--block', '--pid', str(self.worker.pid), '--syscall', operation)
            self.wait_for(lambda: 'Appending events to ./sysmon.log' in read_text(self.console_path))
            result = self.action(operation)
            require(result['result'] == -1 and result['errno'] == errno.EPERM and
                    result['side_effects'] == 0, f"Blocking failed or modified data: {result}")
            replies.append(result)
            self.wait_for(lambda: read_text(self.output / 'sysmon.log').count('blocked=yes') >= index + 1)
            # Receipt of the real text line proves this denied event reached the file.
            self.stop()
        validate_block(read_text(self.output / 'sysmon.log'), self.worker.pid, operations)
        return {'denials': replies, 'color': 'red'}

    def cleanup(self):
        try:
            if self.prepared:
                self.ctl('--off')
        finally:
            for process in (self.collector, self.worker):
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            if self.channel:
                self.channel.close()
            if self.console:
                self.console.close()
            if self.loaded:
                subprocess.run(['rmmod', 'sysmon'], check=True, timeout=10)


def json_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suite', choices=['fsm', 'block'])
    parser.add_argument('--file', type=Path, default=ROOT / 'fsm.json')
    parser.add_argument('--output', type=Path,
                        help='New result directory; missing parents are created (default: unique tests/results directory)')
    parser.add_argument('--timeout', type=float, default=30, help='Seconds per wait (default 30)')
    parser.add_argument('--use-loaded', action='store_true', help='Use the rebuilt, already loaded module; must be off')
    args = parser.parse_args()
    require(0 < args.timeout <= 300, '--timeout must be in (0, 300]')
    states = source = None
    if args.suite == 'fsm':
        with args.file.open('rb') as file:
            source = file.read(65537)
        require(len(source) <= 65536, 'FSM file exceeds 64 KiB')
        data = json.loads(source, object_pairs_hook=json_object)
        require(isinstance(data, dict) and set(data) == {'states'}, 'Expected one states array')
        states = data['states']
        require(isinstance(states, list) and 1 <= len(states) <= 256 and
                all(isinstance(op, str) and op in ('open', 'read', 'write') for op in states),
                'Expected 1–256 open/read/write states')
    require(os.geteuid() == 0, 'Run this live test with sudo')
    require(CTL.is_file() and WORKER.is_file(), 'Run make user tests first')
    lock_path = Path('/run/lock/sysmon-tests.lock')
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output = (args.output or ROOT / 'tests/results' /
                  f'{args.suite}-cli-{time.time_ns()}').resolve()
        require(not output.exists(), f'Output exists: {output}; choose a fresh --output')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.mkdir(exist_ok=False)
        if source is not None:
            (output / 'fsm.json').write_bytes(source)
        test = LiveTest(args, output)
        print(f'Running {args.suite} test; actual sysmonctl log: {output / "sysmon.log"}\n', flush=True)
        report = {'suite': args.suite, 'passed': False}
        if states is not None:
            print(f'FSM file: {args.file.resolve()}\n'
                  f'Expected {len(states)} states: {" -> ".join(states)}\n'
                  f'The test must observe all {len(states)} states before returning to state 1.\n', flush=True)
            report.update(source_file=str(args.file.resolve()), configured_states=states,
                          expected_transitions=len(states))
        try:
            test.prepare()
            report.update(test.fsm(states) if states is not None else test.block())
            report['passed'] = True
        except Exception as exc:
            report['error'] = str(exc)
            raise
        finally:
            try:
                test.cleanup()
            except Exception as exc:
                report.update(passed=False, cleanup_error=str(exc))
                raise
            finally:
                # Test metadata is separate; never synthesize or append sysmon.log.
                (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
                if 'SUDO_UID' in os.environ and 'SUDO_GID' in os.environ:
                    for path in [*output.rglob('*'), output]:
                        os.chown(path, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
        print(f'PASS: {args.suite}; log: {output / "sysmon.log"}\n')


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise RuntimeError(f'Test interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
