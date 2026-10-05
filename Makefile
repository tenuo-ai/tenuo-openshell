.PHONY: bench check demo e2e nat-agent production-quickstart quickstart smoke test test-rust test-python

bench:
	scripts/bench.sh

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

quickstart:
	scripts/quickstart-check.sh

nat-agent:
	TENUO_QS_GUIDE=nat-agent scripts/quickstart-check.sh

production-quickstart:
	scripts/production-quickstart-check.sh
