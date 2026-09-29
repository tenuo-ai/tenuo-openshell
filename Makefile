.PHONY: check demo e2e test test-rust test-python

check: test
	ci/check.sh

test: test-rust test-python

test-rust:
	cargo test --all-targets

test-python:
	uv run --project python/nemo-agent-toolkit-tenuo --extra test pytest python/nemo-agent-toolkit-tenuo/tests -q

demo e2e:
	scripts/openshell-e2e.sh
