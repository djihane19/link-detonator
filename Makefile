PYTHON := .venv/bin/python
IMAGE ?= link-detonator-worker:latest

.PHONY: test dev worker-image

# Offline only: no test loads a real website.
test:
	$(PYTHON) -m pytest

# Runs fixtures in a plain subprocess, with NO sandbox. The app refuses live URLs in this
# mode and shows a permanent "DEV: NOT SANDBOXED" banner.
dev:
	LD_DEV_LOCAL_RUNNER=1 LD_BIND_HOST=127.0.0.1 $(PYTHON) -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Needs Docker.
worker-image:
	docker build -t $(IMAGE) -f worker/Dockerfile worker

# Real model. Refuses to run without VULTR_API_KEY, and needs Docker unless LD_DEV_LOCAL_RUNNER=1.
benchmark:
	$(PYTHON) -m benchmarks.run --model vultr

# A model that obeys every attack. Tests the deterministic layers only.
harness:
	LD_DEV_LOCAL_RUNNER=1 $(PYTHON) -m benchmarks.run --model compromised --out reports/harness-check.json
