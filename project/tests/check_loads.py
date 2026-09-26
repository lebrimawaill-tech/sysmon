#!/usr/bin/env python3
"""Unprivileged checks of timing math and analysis; no module is loaded."""
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import plot_loads

TESTS = Path(__file__).resolve().parent


def write_csv(path, values):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(values[0]))
        writer.writeheader()
        writer.writerows(values)


class WorkloadChecks(unittest.TestCase):
    def test_response_excludes_pacing_sleep(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixture = root / "payload"
            fixture.write_bytes(b"a" * 64)
            binary = TESTS / "bench_impact"
            header = subprocess.check_output([binary, "--header"], text=True)
            output = subprocess.check_output([binary, "--fixture", fixture, "--scenario", "baseline",
                "--rate", "3000", "--duration-ms", "50"], text=True)
            (root / "trials.csv").write_text(header + output)
            (root / "COMPLETE").touch()
            row = list(csv.DictReader(io.StringIO(header + output)))[0]
            self.assertEqual(list(row)[-4:],
                             ["response_p50_ns", "response_p99_ns", "missed_slots", "errors"])
            self.assertNotIn(None, row)
            self.assertGreater(int(row["transactions"]), 0)
            self.assertGreaterEqual(int(row["elapsed_ns"]), 45000000)
            # The loop is paced roughly every millisecond, but useful work is
            # fast cached I/O. Averaging elapsed/N would incorrectly include sleep.
            active = float(row["service_mean_ns"]) * int(row["transactions"])
            self.assertLess(active, int(row["elapsed_ns"]) / 2)
            summary = plot_loads.analyze(root)
            self.assertEqual(summary["groups"][0]["slowdown_pct"], 0)

    def test_unpaced_work_cap_and_cli(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Path(name) / "payload"
            fixture.write_bytes(b"x" * 64)
            binary = TESTS / "bench_latency"
            header = subprocess.check_output([binary, "--header"], text=True)
            output = subprocess.check_output([binary, "--fixture", fixture, "--rate", "0",
                "--max-transactions", "100", "--duration-ms", "1000"], text=True)
            row = list(csv.DictReader(io.StringIO(header + output)))[0]
            self.assertEqual(int(row["transactions"]), 100)
            self.assertEqual(int(row["errors"]), 0)
            invalid = subprocess.run([binary, "--fixture", fixture, "--rate", "-1"], capture_output=True)
            self.assertNotEqual(invalid.returncode, 0)


class AnalysisChecks(unittest.TestCase):
    def fixture(self, root):
        (root / "COMPLETE").touch()
        run = root / "verbose/rate_3000/trial_1"
        run.mkdir(parents=True)
        trial = dict(suite="latency", scenario="verbose", trial=1, pid=42,
                     requested_rate=3000, achieved_rate=3000, transactions=1,
                     start_ns=1000000, end_ns=2000000, elapsed_ns=1000000,
                     service_mean_ns=0, response_p50_ns=0,
                     response_p99_ns=0, missed_slots=0, errors=0)
        write_csv(root / "trials.csv", [trial])
        log = "".join(f"mono_ns={1000000 + i * 1000} seq={i + 1} pid=42 tid=42 rest\n\n" for i in range(3))
        log += "mono_ns=999999 seq=4 pid=42 tid=42 warmup\n"
        log += "mono_ns=1000000 seq=5 pid=43 tid=43 background\n"
        (run / "sysmon.log").write_text(log)
        metrics = [dict(seq=i+1, pid=42, tid=42, syscall="read", blocked=0,
                        capture_mono_ns=1000000+i*1000, receive_mono_ns=1005000+i*1000,
                        append_mono_ns=1008000+i*1000) for i in range(3)]
        write_csv(run / "metrics.csv", metrics)
        fields = dict(capture_n=0, accepted_records=0, delivered_records=0,
                      dropped=0, queue_high=0, read_batches=0)
        write_csv(run / "before.stats", [fields])
        write_csv(run / "after.stats", [dict(fields, capture_n=5, accepted_records=5,
            delivered_records=5, queue_high=3, read_batches=2)])
        return run, metrics

    def test_filter_clocks_and_plot(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            summary = plot_loads.analyze(root)
            group = summary["groups"][0]
            self.assertEqual(group["logged_events"], 3)
            self.assertEqual(group["coverage_pct"], 100)
            self.assertEqual(group["receive_median_us"], 5)
            self.assertEqual(group["append_median_us"], 8)
            subprocess.run([sys.executable, TESTS / "plot_loads.py", "--results", root],
                           check=True, capture_output=True, text=True, timeout=30)
            self.assertEqual(json.loads((root / "summary.json").read_text()), summary)
            self.assertEqual(list(root.rglob("*.tex")), [])
            self.assertTrue((root / "figures/latency_vs_load.pdf").is_file())
            json.dumps(summary, allow_nan=False)
            # Ignore separators, but do not silently accept damaged records.
            with (root / "verbose/rate_3000/trial_1/sysmon.log").open("a") as stream:
                stream.write("not a syscall record\n")
            with self.assertRaisesRegex(ValueError, "malformed log record"):
                plot_loads.analyze(root)

    def test_rejects_invalid_or_missing_metrics(self):
        # Pass when malformed or absent metrics are correctly rejected.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            run, metrics = self.fixture(root)
            metrics[0]["receive_mono_ns"] = 0
            write_csv(run / "metrics.csv", metrics)
            with self.assertRaisesRegex(ValueError, "negative latency"):
                plot_loads.analyze(root)
            (run / "metrics.csv").unlink()
            with self.assertRaises(FileNotFoundError):
                plot_loads.analyze(root)

    def test_rejects_inconsistent_blocking_results(self):
        # Pass when incomplete denial and side effects invalidate a result.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "COMPLETE").touch()
            row = dict(operation="write", trial=1, requested_rate=3000, achieved_rate=3000,
                attempts=100, denied=99, allowed=1, errors=0, blocked_records=99,
                queue_drops=0, side_effects=1, elapsed_ns=33333333)
            write_csv(root / "trials.csv", [row])
            with self.assertRaisesRegex(ValueError, "blocking failed"):
                plot_loads.analyze(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
