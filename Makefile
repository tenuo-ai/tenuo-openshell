.PHONY: check demo e2e smoke test test-rust test-python

check:
	ci/check.sh

test: test-rust test-python

test-rust:
	cargo test --all-targets --locked

test-python:
	uv run --locked --project python/nemo-agent-toolkit-tenuo --extra test pytest python/nemo-agent-toolkit-tenuo/tests -q

demo e2e:
	scripts/openshell-e2e.sh

smoke:
	scripts/onboarding-smoke.sh
