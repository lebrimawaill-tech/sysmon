.PHONY: all kmod user tests check bench perf latency impact blocking plots legacy-plots report report-evidence install uninstall clean

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
RESULTS ?= tests/results
FIGURES ?= tests/figures
PYTHON ?= python3

all: kmod user

kmod:
	$(MAKE) -C kmod

user:
	$(MAKE) -C user

tests:
	$(MAKE) -C tests

check: user tests
	$(MAKE) -C tests check

bench: tests

# Each direct runner owns its module and refuses an already loaded one.
perf: latency impact blocking

latency: kmod user tests
	./tests/run_latency.sh --output "$(RESULTS)/latency"

impact: kmod user tests
	./tests/run_impact.sh --output "$(RESULTS)/impact"

blocking: kmod user tests
	./tests/run_block.sh --output "$(RESULTS)/block"

plots:
	$(PYTHON) tests/plot_loads.py --results "$(RESULTS)"

# Keep the original measured tables available in the report as an archive.
legacy-plots:
	$(PYTHON) tests/plot_perf.py --results "$(RESULTS)" --figures "$(FIGURES)"

report:
	$(PYTHON) tests/plot_loads.py --results "$(RESULTS)" --report-tex
	$(PYTHON) tests/analyze_timestamp_cache.py --results "$(RESULTS)/timestamp-cache-comparison" --report-tex
	$(PYTHON) tests/plot_perf.py --design-only --figures "$(FIGURES)"
	$(PYTHON) tests/report_evidence.py --figures "$(FIGURES)" --results "$(RESULTS)"
	pdflatex -interaction=nonstopmode -halt-on-error '\def\ResultDir{$(RESULTS)}\def\FigureDir{$(FIGURES)}\input{report.tex}'
	pdflatex -interaction=nonstopmode -halt-on-error '\def\ResultDir{$(RESULTS)}\def\FigureDir{$(FIGURES)}\input{report.tex}'

report-evidence:
	$(PYTHON) tests/report_evidence.py --refresh --figures "$(FIGURES)"

install: user
	install -d $(BINDIR)
	install -m 755 user/sysmonctl $(BINDIR)/sysmonctl

uninstall:
	rm -f $(BINDIR)/sysmonctl

clean:
	$(MAKE) -C kmod clean
	$(MAKE) -C user clean
	$(MAKE) -C tests clean

# Module ownership is process-wide; never run the suites concurrently.
.NOTPARALLEL: perf latency impact blocking
