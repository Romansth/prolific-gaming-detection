PY ?= python3
VERSION := $(shell $(PY) -c "import fraudscreen; print(fraudscreen.__version__)")

.PHONY: test dist synth clean
test:
	$(PY) -m unittest discover -q -s tests -t .
	$(PY) -m unittest discover -q -s privacy/tests -t .

synth:
	$(PY) -m tests.synth /tmp/fraudscreen-synth

# Allow-list: only the package, its tests and the launchers go into the zip. Nothing written by a
# run (reports, redacted copies, keys) can be picked up, whatever folder it landed in.
DIST_FILES = fraudscreen privacy tests tools .claude README.md CLAUDE.md Makefile setup.sh setup.ps1 screen.sh screen.ps1 .gitignore .ignore \
             raw-data/.gitkeep data-redacted/.gitkeep reports/.gitkeep reports-team/.gitkeep
dist:
	rm -f ../prolific-gaming-detection-$(VERSION).zip
	cd .. && zip -qr prolific-gaming-detection-$(VERSION).zip $(addprefix $(notdir $(CURDIR))/,$(DIST_FILES)) -x '*__pycache__*' '*.pyc' '*.DS_Store'
	@echo "wrote ../prolific-gaming-detection-$(VERSION).zip"

clean:
	find . -name __pycache__ -type d -prune -exec rm -r {} +
